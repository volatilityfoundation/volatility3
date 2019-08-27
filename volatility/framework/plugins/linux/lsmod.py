# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl_v1.0
#
"""A module containing a collection of plugins that produce data
typically found in Linux's /proc file system.
"""

from typing import List

from volatility.framework import contexts
from volatility.framework import renderers, constants, interfaces
from volatility.framework.automagic import linux
from volatility.framework.configuration import requirements
from volatility.framework.interfaces import plugins
from volatility.framework.objects import utility
from volatility.framework.renderers import format_hints


class Lsmod(plugins.PluginInterface):
    """Lists loaded kernel modules"""

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.TranslationLayerRequirement(
                name = 'primary', description = 'Memory layer for the kernel', architectures = ["Intel32", "Intel64"]),
            requirements.SymbolTableRequirement(name = "vmlinux", description = "Linux kernel symbols")
        ]

    @classmethod
    def list_modules(cls, context: interfaces.context.ContextInterface, layer_name: str, vmlinux_symbols: str):
        """Lists all the modules in the primary layer"""
        linux.LinuxUtilities.aslr_mask_symbol_table(context, vmlinux_symbols, layer_name)

        vmlinux = contexts.Module(context, vmlinux_symbols, layer_name, 0)

        modules = vmlinux.object_from_symbol(symbol_name = "modules").cast("list_head")

        table_name = modules.vol.type_name.split(constants.BANG)[0]

        for module in modules.to_list(table_name + constants.BANG + "module", "list"):
            yield module

    def _generator(self):
        for module in self.list_modules(self.context, self.config['primary'], self.config['vmlinux']):

            mod_size = module.get_init_size() + module.get_core_size()

            mod_name = utility.array_to_string(module.name)

            yield 0, (format_hints.Hex(module.vol.offset), mod_name, mod_size)

    def run(self):
        return renderers.TreeGrid([("Offset", format_hints.Hex), ("Name", str), ("Size", int)], self._generator())
