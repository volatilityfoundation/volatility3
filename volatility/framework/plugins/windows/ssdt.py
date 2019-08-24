# This file was contributed to the Volatility Framework Version 3.
# Copyright (C) 2018 Volatility Foundation.
#
# THE LICENSED WORK IS PROVIDED UNDER THE TERMS OF THE Volatility Contributors
# Public License V1.0("LICENSE") AS FIRST COMPLETED BY: Volatility Foundation,
# Inc. ANY USE, PUBLIC DISPLAY, PUBLIC PERFORMANCE, REPRODUCTION OR DISTRIBUTION
# OF, OR PREPARATION OF SUBSEQUENT WORKS, DERIVATIVE WORKS OR DERIVED WORKS BASED
# ON, THE LICENSED WORK CONSTITUTES RECIPIENT'S ACCEPTANCE OF THIS LICENSE AND ITS
# TERMS, WHETHER OR NOT SUCH RECIPIENT READS THE TERMS OF THE LICENSE. "LICENSED
# WORK,” “RECIPIENT" AND “DISTRIBUTOR" ARE DEFINED IN THE LICENSE. A COPY OF THE
# LICENSE IS LOCATED IN THE TEXT FILE ENTITLED "LICENSE.txt" ACCOMPANYING THE
# CONTENTS OF THIS FILE. IF A COPY OF THE LICENSE DOES NOT ACCOMPANY THIS FILE, A
# COPY OF THE LICENSE MAY ALSO BE OBTAINED AT THE FOLLOWING WEB SITE:
# https://www.volatilityfoundation.org/license/vcpl_v1.0
#
# Software distributed under the License is distributed on an "AS IS" basis,
# WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License for the
# specific language governing rights and limitations under the License.
#

import os
from typing import Any, Iterator, List, Tuple

from volatility.framework import constants, interfaces
from volatility.framework import contexts
from volatility.framework import exceptions, symbols
from volatility.framework import renderers
from volatility.framework.configuration import requirements
from volatility.framework.constants import windows as windows_constants
from volatility.framework.interfaces import plugins
from volatility.framework.renderers import format_hints
from volatility.plugins.windows import modules


class SSDT(plugins.PluginInterface):
    """Lists the system call table"""

    _version = (1, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.TranslationLayerRequirement(
                name = 'primary', description = 'Memory layer for the kernel', architectures = ["Intel32", "Intel64"]),
            requirements.SymbolTableRequirement(name = "nt_symbols", description = "Windows kernel symbols"),
            requirements.PluginRequirement(name = 'modules', plugin = modules.Modules, version = (1, 0, 0)),
        ]

    @classmethod
    def build_module_collection(cls, context: interfaces.context.ContextInterface, layer_name: str,
                                symbol_table: str) -> contexts.ModuleCollection:
        """Builds a collection of modules"""

        mods = modules.Modules.list_modules(context, layer_name, symbol_table)
        context_modules = []

        for mod in mods:

            try:
                module_name_with_ext = mod.BaseDllName.get_string()
            except exceptions.InvalidAddressException:
                # there's no use for a module with no name?
                continue

            module_name = os.path.splitext(module_name_with_ext)[0]

            symbol_table_name = None
            if module_name in windows_constants.KERNEL_MODULE_NAMES:
                symbol_table_name = symbol_table

            context_module = contexts.SizedModule(
                context, module_name, layer_name, mod.DllBase, mod.SizeOfImage, symbol_table_name = symbol_table_name)

            context_modules.append(context_module)

        return contexts.ModuleCollection(context_modules)

    def _generator(self) -> Iterator[Tuple[int, Tuple[int, int, Any, Any]]]:

        layer_name = self.config['primary']
        collection = self.build_module_collection(self.context, self.config["primary"], self.config["nt_symbols"])

        kvo = self.context.layers[layer_name].config['kernel_virtual_offset']
        ntkrnlmp = self.context.module(self.config["nt_symbols"], layer_name = layer_name, offset = kvo)

        # this is just one way to enumerate the native (NT) service table.
        # to do the same thing for the Win32K service table, we would need Win32K.sys symbol support
        ## we could also find nt!KeServiceDescriptorTable (NT) and KeServiceDescriptorTableShadow (NT, Win32K)
        service_table_address = ntkrnlmp.get_symbol("KiServiceTable").address
        service_limit_address = ntkrnlmp.get_symbol("KiServiceLimit").address
        service_limit = ntkrnlmp.object(object_type = "int", offset = service_limit_address)

        # on 32-bit systems the table indexes are 32-bits and contain pointers (unsigned)
        # on 64-bit systems the indexes are also 32-bits but they're offsets from the
        # base address of the table and can be negative, so we need a signed data type
        is_kernel_64 = symbols.symbol_table_is_64bit(self.context, self.config["nt_symbols"])
        if is_kernel_64:
            array_subtype = "long"

            def kvo_calulator(func: int) -> int:
                return kvo + service_table_address + (func >> 4)

            find_address = kvo_calulator
        else:
            array_subtype = "unsigned long"

            def passthrough(func: int) -> int:
                return func

            find_address = passthrough

        functions = ntkrnlmp.object(
            object_type = "array",
            offset = service_table_address,
            subtype = ntkrnlmp.get_type(array_subtype),
            count = service_limit)

        for idx, function_obj in enumerate(functions):

            function = find_address(function_obj)
            module_symbols = collection.get_module_symbols_by_absolute_location(function)

            for module_name, symbol_generator in module_symbols:
                symbols_found = False

                for symbol in symbol_generator:
                    symbols_found = True
                    yield (0, (idx, format_hints.Hex(function), module_name, symbol.split(constants.BANG)[1]))

                if not symbols_found:
                    yield (0, (idx, format_hints.Hex(function), module_name, renderers.NotAvailableValue()))

    def run(self) -> renderers.TreeGrid:
        return renderers.TreeGrid([("Index", int), ("Address", format_hints.Hex), ("Module", str), ("Symbol", str)],
                                  self._generator())
