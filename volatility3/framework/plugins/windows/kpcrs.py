# This file is Copyright 2024 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

import logging

from typing import Iterator, Generator, List, Tuple

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
    _version = (2, 0, 0)

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
    ) -> Generator[Tuple[interfaces.objects.ObjectInterface, int], None, None]:
        """Returns the KPCR structure for each processor

        Args:
            context: The context to retrieve required elements (layers, symbol tables) from
            kernel_module_name: The name of the kernel module on which to operate

        Returns:
            The _KPCR structure for each processor
        """

        kernel = context.modules[kernel_module_name]
        kernel_layer = context.layers[kernel.layer_name]

        kpcr_type = kernel.get_type("_KPCR")

        reloff = kpcr_type.relative_child_offset("Prcb")

        if kpcr_type.has_member("CurrentPrcb"):
            kpcr_member = "CurrentPrcb"
        else:
            kpcr_member = "Prcb"

        cpu_count_offset = kernel.get_symbol("KeNumberProcessors").address

        cpu_count = kernel.object(
            object_type="unsigned int",
            layer_name=kernel_layer.name,
            offset=cpu_count_offset,
        )

        processor_block = kernel.object(
            object_type="pointer",
            layer_name=kernel_layer.name,
            offset=kernel.get_symbol("KiProcessorBlock").address,
        )

        processor_pointers = utility.array_of_pointers(
            context=context,
            array=processor_block,
            count=cpu_count,
            subtype=kernel.symbol_table_name + constants.BANG + "_KPRCB",
        )

        for pointer in processor_pointers:
            kprcb = pointer.dereference()

            object_address = kprcb.vol.offset - reloff

            if not kernel_layer.is_valid(kprcb.vol.offset):
                continue

            kpcr = kernel.object("_KPCR", offset=object_address, absolute=True)

            yield kpcr, kpcr.member(kpcr_member)

    def _generator(self) -> Iterator[Tuple]:

        for kpcr, current_prcb in self.list_kpcrs(self.context, self.config["kernel"]):
            yield (
                0,
                (
                    format_hints.Hex(kpcr.vol.offset),
                    format_hints.Hex(current_prcb),
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
