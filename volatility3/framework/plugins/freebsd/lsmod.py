# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
"""A module containing a collection of plugins that produce data typically
found in Freebsd's kldstat -v command."""

from typing import List

from volatility3.framework import renderers, interfaces
from volatility3.framework.configuration import requirements
from volatility3.framework.interfaces import plugins
from volatility3.framework.objects import utility
from volatility3.framework.renderers import format_hints


class LsMod(plugins.PluginInterface):
    """Lists loaded kernel modules."""

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
    def list_modules(cls, context: interfaces.context.ContextInterface, kernel_module_name: str):
        """Lists all the modules in the primary layer.

        Args:
            context: The context to retrieve required elements (layers, symbol tables) from
            kernel_module_name: The name of the the kernel module on which to operate

        Yields:
            Modules
        """
        kernel = context.modules[kernel_module_name]
        kernel_layer = context.layers[kernel.layer_name]

        modules = kernel.object_from_symbol(symbol_name = "modules")
        module = modules.tqh_first

        while module != 0:
            yield module.dereference()
            module = module.link.tqe_next

    def _generator(self):
        for module in self.list_modules(self.context, self.config["kernel"]):
            module_id = module.id
            module_name = utility.pointer_to_string(module.name, 32)
            module_file_pathname = utility.pointer_to_string(module.file.pathname, 1024)

            yield 0, (format_hints.Hex(module.vol.offset), module_id, module_name, module_file_pathname)

    def run(self):
        return renderers.TreeGrid(
            [("Offset", format_hints.Hex), ("Id", int), ("Name", str), ("Kld", str)],
            self._generator(),
        )
