"""A module containing a collection of plugins that produce data
typically found in Linux's /proc file system.
"""

from volatility.framework import renderers, constants, interfaces
from volatility.framework.automagic import linux
from volatility.framework.configuration import requirements
from volatility.framework.interfaces import plugins
from volatility.framework.objects import utility
from volatility.framework.renderers import format_hints


class Lsmod(plugins.PluginInterface):
    """Lists loaded kernel modules"""

    @classmethod
    def get_requirements(cls):
        return [requirements.TranslationLayerRequirement(name = 'primary',
                                                         description = 'Kernel Address Space',
                                                         architectures = ["Intel32", "Intel64"]),
                requirements.SymbolRequirement(name = "vmlinux",
                                               description = "Linux Kernel")]

    @classmethod
    def list_modules(cls,
                     context: interfaces.context.ContextInterface,
                     layer_name: str,
                     vmlinux_symbols: str):
        """Lists all the modules in the primary layer"""

        _, aslr_shift = linux.LinuxUtilities.find_aslr(context, vmlinux_symbols, layer_name)
        vmlinux = context.module(vmlinux_symbols, layer_name, aslr_shift)

        module_head_addr = vmlinux.get_symbol("modules").address

        modules = vmlinux.object(type_name = "list_head", offset = module_head_addr)

        table_name = modules.vol.type_name.split(constants.BANG)[0]

        for module in modules.to_list("{}{}module".format(table_name, constants.BANG), "list"):
            yield module

    def _generator(self):
        for module in self.list_modules(self.context,
                                        self.config['primary'],
                                        self.config['vmlinux']):

            mod_size = module.get_init_size() + module.get_core_size()

            mod_name = utility.array_to_string(module.name)

            yield 0, (format_hints.Hex(module.vol.offset), mod_name, mod_size)

    def run(self):
        return renderers.TreeGrid(
            [("Offset", format_hints.Hex),
             ("Name", str),
             ("Size", int)],
            self._generator())
