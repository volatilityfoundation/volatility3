# This file is Copyright 2024 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

import logging
from typing import List

from volatility3.framework import constants, exceptions, interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.renderers import format_hints
from volatility3.plugins.windows import ssdt
from volatility3.plugins.windows.registry import hivelist

vollog = logging.getLogger(__name__)


class GetCellRoutine(interfaces.plugins.PluginInterface):
    """Reports registry hives with a hooked GetCellRoutine handler"""

    _required_framework_version = (2, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Windows kernel",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.PluginRequirement(
                name="hivelist", plugin=hivelist.HiveList, version=(1, 0, 0)
            ),
            requirements.PluginRequirement(
                name="ssdt", plugin=ssdt.SSDT, version=(1, 0, 0)
            ),
        ]

    def _generator(self):
        kernel = self.context.modules[self.config["kernel"]]

        collection = ssdt.SSDT.build_module_collection(
            self.context, kernel.layer_name, kernel.symbol_table_name
        )

        # walk each hive and validate that the GetCellRoutine handler
        # is inside of the kernel (ntoskrnl)
        for hive_object in hivelist.HiveList.list_hives(
            context=self.context,
            base_config_path=self.config_path,
            layer_name=kernel.layer_name,
            symbol_table=kernel.symbol_table_name,
        ):
            hive = hive_object.hive

            try:
                cellroutine = hive.GetCellRoutine
            except exceptions.InvalidAddressException:
                continue

            module_symbols = list(
                collection.get_module_symbols_by_absolute_location(cellroutine)
            )

            if module_symbols:
                for module_name, _ in module_symbols:
                    # GetCellRoutine handlers should only be in the kernel
                    if module_name not in constants.windows.KERNEL_MODULE_NAMES:
                        yield (
                            0,
                            (
                                format_hints.Hex(hive.vol.offset),
                                hive_object.get_name() or "",
                                module_name,
                                format_hints.Hex(cellroutine),
                            ),
                        )
            # Doesn't map to any module...
            else:
                yield (
                    0,
                    (
                        format_hints.Hex(hive.vol.offset),
                        hive_object.get_name() or "",
                        renderers.NotAvailableValue(),
                        format_hints.Hex(cellroutine),
                    ),
                )

    def run(self):
        return renderers.TreeGrid(
            [
                ("Hive Offset", renderers.format_hints.Hex),
                ("Hive Name", str),
                ("GetCellRoutine Module", str),
                ("GetCellRoutine Handler", renderers.format_hints.Hex),
            ],
            self._generator(),
        )
