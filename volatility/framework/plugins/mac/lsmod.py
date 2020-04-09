# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
"""A module containing a collection of plugins that produce data typically
found in Mac's lsmod command."""
from volatility.framework import renderers, interfaces, contexts
from volatility.framework.automagic import mac
from volatility.framework.configuration import requirements
from volatility.framework.interfaces import plugins
from volatility.framework.objects import utility
from volatility.framework.renderers import format_hints


class Lsmod(plugins.PluginInterface):
    """Lists loaded kernel modules."""

    _version = (1, 0, 0)

    @classmethod
    def get_requirements(cls):
        return [
            requirements.TranslationLayerRequirement(name = 'primary',
                                                     description = 'Memory layer for the kernel',
                                                     architectures = ["Intel32", "Intel64"]),
            requirements.SymbolTableRequirement(name = "darwin", description = "Linux kernel symbols")
        ]

    @classmethod
    def list_modules(cls, context: interfaces.context.ContextInterface, layer_name: str, darwin_symbols: str):
        """Lists all the modules in the primary layer.

        Args:
            context: The context to retrieve required elements (layers, symbol tables) from
            layer_name: The name of the layer on which to operate
            darwin_symbols: The name of the table containing the kernel symbols

        Returns:
            A list of modules from the `layer_name` layer
        """
        masked_darwin_symbols = mac.MacUtilities.aslr_mask_symbol_table(context, darwin_symbols, layer_name)

        kernel = contexts.Module(context, masked_darwin_symbols, layer_name, 0)

        kmod_ptr = kernel.object_from_symbol(symbol_name = "kmod")

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
