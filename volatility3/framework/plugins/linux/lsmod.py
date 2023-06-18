# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
"""A module containing a collection of plugins that produce data typically
found in Linux's /proc file system."""

import logging
from typing import List, Iterable

from volatility3.framework import exceptions, renderers, constants, interfaces
from volatility3.framework.configuration import requirements
from volatility3.framework.interfaces import plugins
from volatility3.framework.objects import utility
from volatility3.framework.renderers import format_hints

vollog = logging.getLogger(__name__)


class Lsmod(plugins.PluginInterface):
    """Lists loaded kernel modules."""

    _required_framework_version = (2, 0, 0)
    _version = (2, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Linux kernel",
                architectures=["Intel32", "Intel64"],
            ),
        ]

    @classmethod
    def list_modules(
        cls, context: interfaces.context.ContextInterface, vmlinux_module_name: str
    ) -> Iterable[interfaces.objects.ObjectInterface]:
        """Lists all the modules in the primary layer.

        Args:
            context: The context to retrieve required elements (layers, symbol tables) from
            layer_name: The name of the layer on which to operate
            vmlinux_symbols: The name of the table containing the kernel symbols

        Yields:
            The modules present in the `layer_name` layer's modules list

        This function will throw a SymbolError exception if kernel module support is not enabled.
        """
        vmlinux = context.modules[vmlinux_module_name]

        modules = vmlinux.object_from_symbol(symbol_name="modules").cast("list_head")

        table_name = modules.vol.type_name.split(constants.BANG)[0]

        for module in modules.to_list(table_name + constants.BANG + "module", "list"):
            yield module

    def _generator(self):
        try:
            for module in self.list_modules(self.context, self.config["kernel"]):
                mod_size = module.get_init_size() + module.get_core_size()

                mod_name = utility.array_to_string(module.name)

                yield 0, (format_hints.Hex(module.vol.offset), mod_name, mod_size)

        except exceptions.SymbolError:
            vollog.debug(
                "The required symbol 'module' is not present in symbol table. Please check that kernel modules are enabled for the system under analysis."
            )

    def run(self):
        return renderers.TreeGrid(
            [("Offset", format_hints.Hex), ("Name", str), ("Size", int)],
            self._generator(),
        )
