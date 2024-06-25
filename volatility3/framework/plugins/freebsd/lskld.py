# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
"""A module containing a collection of plugins that produce data typically
found in Freebsd's kldstat command."""

from typing import List

from volatility3.framework import renderers, interfaces
from volatility3.framework.configuration import requirements
from volatility3.framework.interfaces import plugins
from volatility3.framework.objects import utility
from volatility3.framework.renderers import format_hints


class LsKld(plugins.PluginInterface):
    """Lists loaded kernel klds."""

    _required_framework_version = (2, 0, 0)

    _version = (1, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(
                name = "kernel",
                description = "Kernel module for the OS",
                architectures = ["Intel32", "Intel64"],
            ),
        ]

    @classmethod
    def list_klds(cls, context: interfaces.context.ContextInterface, kernel_module_name: str):
        """Lists all the klds in the primary layer.

        Args:
            context: The context to retrieve required elements (layers, symbol tables) from
            kernel_module_name: The name of the the kernel module on which to operate

        Yields:
            Klds
        """
        kernel = context.modules[kernel_module_name]
        kernel_layer = context.layers[kernel.layer_name]

        linker_files = kernel.object_from_symbol(symbol_name = "linker_files")
        linker_file = linker_files.tqh_first

        while linker_file != 0:
            yield linker_file.dereference()
            linker_file = linker_file.link.tqe_next

    def _generator(self):
        for kld in self.list_klds(self.context, self.config["kernel"]):
            kld_id = kld.id
            kld_refs = kld.refs
            kld_size = kld.size
            kld_address = kld.address
            kld_pathname = utility.pointer_to_string(kld.pathname, 1024)

            yield 0, (format_hints.Hex(kld.vol.offset), kld_id, kld_refs, format_hints.Hex(kld_size),
                      format_hints.Hex(kld_address), kld_pathname)

    def run(self):
        return renderers.TreeGrid(
            [("Offset", format_hints.Hex), ("Id", int), ("Refs", int), ("Size", format_hints.Hex),
             ("Address", format_hints.Hex), ("Name", str)],
            self._generator(),
        )
