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

import time
from typing import List

import volatility.framework.interfaces.plugins as plugins
from volatility.framework import constants, interfaces, layers
from volatility.framework.configuration import requirements
from volatility.framework.renderers import TreeGrid
from volatility.framework.symbols.windows.kdbg import KdbgIntermedSymbols
from volatility.framework.symbols.windows.pe import PEIntermedSymbols


class Info(plugins.PluginInterface):
    """Show OS & kernel details of the memory sample being analyzed"""

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.TranslationLayerRequirement(
                name = 'primary', description = 'Kernel Address Space', architectures = ["Intel32", "Intel64"]),
            requirements.SymbolRequirement(name = "nt_symbols", description = "Windows OS")
        ]

    def get_depends(self, layer_name: str, index: int = 0):
        """List the dependencies of a given layer.

        Args:
            layer_name: the name of the starting layer
            index: the index/order of the layer
        """
        layer = self.context.memory[layer_name]
        yield index, layer
        try:
            for depends in layer.dependencies:
                for j, dep in self.get_depends(depends, index + 1):
                    yield j, self.context.memory[dep.name]
        except AttributeError:
            # FileLayer won't have dependencies
            pass

    def _generator(self):

        virtual_layer_name = self.config["primary"]
        virtual_layer = self.context.memory[virtual_layer_name]
        if not isinstance(virtual_layer, layers.intel.Intel):
            raise TypeError("Virtual Layer is not an intel layer")

        native_types = self.context.symbol_space[self.config["nt_symbols"]].natives

        kdbg_table_name = KdbgIntermedSymbols.create(
            self.context, self.config_path, "windows", "kdbg", native_types = native_types)

        pe_table_name = PEIntermedSymbols.create(self.context, self.config_path, "windows", "pe")

        kvo = virtual_layer.config["kernel_virtual_offset"]

        ntkrnlmp = self.context.module(self.config["nt_symbols"], layer_name = virtual_layer_name, offset = kvo)

        kdbg_offset = ntkrnlmp.get_symbol("KdDebuggerDataBlock").address

        kdbg = self.context.object(
            kdbg_table_name + constants.BANG + "_KDDEBUGGER_DATA64",
            offset = kvo + kdbg_offset,
            layer_name = virtual_layer_name)

        yield (0, ("Memory Location", self.config["primary.memory_layer.location"]))
        yield (0, ("Kernel Base", hex(self.config["primary.kernel_virtual_offset"])))
        yield (0, ("DTB", hex(self.config["primary.page_map_offset"])))
        yield (0, ("Symbols", self.config["nt_symbols.isf_url"]))

        for i, layer in self.get_depends("primary"):
            yield (0, (layer.name, "{} {}".format(i, layer.__class__.__name__)))

        if kdbg.Header.OwnerTag == 0x4742444B:

            yield (0, ("KdDebuggerDataBlock", hex(kdbg.vol.offset)))
            yield (0, ("NTBuildLab", kdbg.get_build_lab()))
            yield (0, ("CSDVersion", str(kdbg.get_csdversion())))

        vers_offset = ntkrnlmp.get_symbol("KdVersionBlock").address

        vers = ntkrnlmp.object(
            type_name = "_DBGKD_GET_VERSION64", layer_name = virtual_layer_name, offset = kvo + vers_offset)

        yield (0, ("KdVersionBlock", hex(vers.vol.offset)))
        yield (0, ("Major/Minor", "{0}.{1}".format(vers.MajorVersion, vers.MinorVersion)))
        yield (0, ("MachineType", str(vers.MachineType)))

        cpu_count_offset = ntkrnlmp.get_symbol("KeNumberProcessors").address

        cpu_count = ntkrnlmp.object(
            type_name = "unsigned int", layer_name = virtual_layer_name, offset = kvo + cpu_count_offset)

        yield (0, ("KeNumberProcessors", str(cpu_count)))

        # this is a hard-coded address in the Windows OS
        if virtual_layer.bits_per_register == 32:
            kuser_addr = 0xFFDF0000
        else:
            kuser_addr = 0xFFFFF78000000000

        kuser = ntkrnlmp.object(type_name = "_KUSER_SHARED_DATA", layer_name = virtual_layer_name, offset = kuser_addr)

        yield (0, ("SystemTime", str(kuser.SystemTime.get_time())))
        yield (0, ("NtSystemRoot",
                   str(kuser.NtSystemRoot.cast("string", encoding = "utf-16", errors = "replace", max_length = 260))))
        yield (0, ("NtProductType", str(kuser.NtProductType.description)))
        yield (0, ("NtMajorVersion", str(kuser.NtMajorVersion)))
        yield (0, ("NtMinorVersion", str(kuser.NtMinorVersion)))
        # yield (0, ("KdDebuggerEnabled", "True" if ord(kuser.KdDebuggerEnabled) else "False"))
        # yield (0, ("SafeBootMode", "True" if ord(kuser.SafeBootMode) else "False"))

        dos_header = self.context.object(
            pe_table_name + constants.BANG + "_IMAGE_DOS_HEADER", offset = kvo, layer_name = virtual_layer_name)

        nt_header = dos_header.get_nt_header()

        yield (0, ("PE MajorOperatingSystemVersion", str(nt_header.OptionalHeader.MajorOperatingSystemVersion)))
        yield (0, ("PE MinorOperatingSystemVersion", str(nt_header.OptionalHeader.MinorOperatingSystemVersion)))

        yield (0, ("PE Machine", str(nt_header.FileHeader.Machine)))
        yield (0, ("PE TimeDateStamp", time.asctime(time.gmtime(nt_header.FileHeader.TimeDateStamp))))

    def run(self):

        return TreeGrid([("Variable", str), ("Value", str)], self._generator())
