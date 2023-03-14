# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
"""A module containing a collection of plugins that produce data typically
found in Mac's lsmod command."""
from typing import Set

from volatility3.framework import renderers, interfaces, exceptions
from volatility3.framework.configuration import requirements
from volatility3.framework.interfaces import plugins
from volatility3.framework.objects import utility
from volatility3.framework.renderers import format_hints


class Lsmod(plugins.PluginInterface):
    """Lists loaded kernel modules."""

    _required_framework_version = (2, 0, 0)

    _version = (2, 0, 0)

    @classmethod
    def get_requirements(cls):
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Kernel module for the OS",
                architectures=["Intel32", "Intel64"],
            ),
        ]

    @classmethod
    def list_modules(
        cls, context: interfaces.context.ContextInterface, darwin_module_name: str
    ):
        """Lists all the modules in the primary layer.

        Args:
            context: The context to retrieve required elements (layers, symbol tables) from
            layer_name: The name of the layer on which to operate
            darwin_symbols: The name of the table containing the kernel symbols

        Returns:
            A list of modules from the `layer_name` layer
        """
        kernel = context.modules[darwin_module_name]
        kernel_layer = context.layers[kernel.layer_name]

        kmod_ptr = kernel.object_from_symbol(symbol_name="kmod")

        try:
            kmod = kmod_ptr.dereference().cast("kmod_info")
        except exceptions.InvalidAddressException:
            return  # Generation finished

        yield kmod

        try:
            kmod = kmod.next
        except exceptions.InvalidAddressException:
            return  # Generation finished

        seen: Set = set()

        while kmod != 0 and kmod not in seen and len(seen) < 1024:
            kmod_obj = kmod.dereference()

            if not kernel_layer.is_valid(kmod_obj.vol.offset, kmod_obj.vol.size):
                break

            seen.add(kmod)

            yield kmod

            try:
                kmod = kmod.next
            except exceptions.InvalidAddressException:
                return
        return  # Generation finished

    def _generator(self):
        for module in self.list_modules(self.context, self.config["kernel"]):
            mod_name = utility.array_to_string(module.name)
            mod_size = module.size

            yield 0, (format_hints.Hex(module.vol.offset), mod_name, mod_size)

    def run(self):
        return renderers.TreeGrid(
            [("Offset", format_hints.Hex), ("Name", str), ("Size", int)],
            self._generator(),
        )
