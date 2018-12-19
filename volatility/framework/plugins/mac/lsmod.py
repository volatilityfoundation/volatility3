"""A module containing a collection of plugins that produce data
typically found in Mac's lsmod command.
"""

from volatility.framework import renderers, interfaces
from volatility.framework.automagic import mac
from volatility.framework.configuration import requirements
from volatility.framework.interfaces import plugins
from volatility.framework.objects import utility
from volatility.framework.renderers import format_hints


class Lsmod(plugins.PluginInterface):
    """Lists loaded kernel modules"""

    @classmethod
    def get_requirements(cls):
        return [
            requirements.TranslationLayerRequirement(
                name = 'primary', description = 'Kernel Address Space', architectures = ["Intel32", "Intel64"]),
            requirements.SymbolRequirement(name = "darwin", description = "Linux Kernel")
        ]

    @classmethod
    def list_modules(cls, context: interfaces.context.ContextInterface, layer_name: str, darwin_symbols: str):
        """Lists all the modules in the primary layer"""

        aslr_shift = mac.MacUtilities.find_aslr(context, darwin_symbols, layer_name)

        darwin = context.module(darwin_symbols, layer_name, aslr_shift)

        kmod_ptr = darwin.object(symbol_name = "kmod")

        # TODO - use smear-proof list walking API after dev release
        kmod = kmod_ptr.dereference().cast("kmod_info")
        while kmod != 0:
            yield kmod
            kmod = kmod.next

    def _generator(self):
        for module in self.list_modules(self.context, self.config['primary'], self.config['darwin']):

            mod_name = utility.array_to_string(module.name)
            mod_size = module.size

            yield 0, (format_hints.Hex(module.vol.offset), mod_name, mod_size)

    def run(self):
        return renderers.TreeGrid([("Offset", format_hints.Hex), ("Name", str), ("Size", int)], self._generator())
