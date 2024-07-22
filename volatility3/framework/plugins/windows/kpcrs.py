# This file is Copyright 2024 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

import logging

from typing import Iterator, List, Tuple

from volatility3.framework import (
    renderers,
    interfaces,
    constants,
)
from volatility3.framework.configuration import requirements
from volatility3.framework.objects import utility
from volatility3.framework.renderers import format_hints

vollog = logging.getLogger(__name__)


class KPCRs(interfaces.plugins.PluginInterface):
    """Print KPCR structure for each processor"""

    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Windows kernel",
                architectures=["Intel32", "Intel64"],
            ),
        ]

    @classmethod
    def list_kpcrs(
        cls,
        context: interfaces.context.ContextInterface,
        kernel_module_name: str,
        layer_name: str,
        symbol_table: str,
    ) -> interfaces.objects.ObjectInterface:
        """Returns the KPCR structure for each processor

        Args:
            context: The context to retrieve required elements (layers, symbol tables) from
            kernel_module_name: The name of the kernel module on which to operate
            layer_name: The name of the layer on which to operate
            symbol_table: The name of the table containing the kernel symbols

        Returns:
            The _KPCR structure for each processor
        """

        kernel = context.modules[kernel_module_name]
        cpu_count_offset = kernel.get_symbol("KeNumberProcessors").address
        cpu_count = kernel.object(
            object_type="unsigned int", layer_name=layer_name, offset=cpu_count_offset
        )
        processor_block = kernel.object(
            object_type="pointer",
            layer_name=layer_name,
            offset=kernel.get_symbol("KiProcessorBlock").address,
        )
        processor_pointers = utility.array_of_pointers(
            context=context,
            array=processor_block,
            count=cpu_count,
            subtype=symbol_table + constants.BANG + "_KPRCB",
        )
        for pointer in processor_pointers:
            kprcb = pointer.dereference()
            reloff = kernel.get_type("_KPCR").relative_child_offset("Prcb")
            kpcr = context.object(
                symbol_table + constants.BANG + "_KPCR",
                offset=kprcb.vol.offset - reloff,
                layer_name=layer_name,
            )
            yield kpcr

    def _generator(self) -> Iterator[Tuple]:
        kernel = self.context.modules[self.config["kernel"]]
        layer_name = kernel.layer_name
        symbol_table = kernel.symbol_table_name

        for kpcr in self.list_kpcrs(
            self.context, self.config["kernel"], layer_name, symbol_table
        ):
            yield (
                0,
                (
                    format_hints.Hex(kpcr.vol.offset),
                    format_hints.Hex(kpcr.CurrentPrcb),
                ),
            )

    def run(self):
        return renderers.TreeGrid(
            [
                ("Offset", format_hints.Hex),
                ("PRCB Offset", format_hints.Hex),
            ],
            self._generator(),
        )
