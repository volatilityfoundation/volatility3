# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
from typing import Iterator, List, Tuple
from volatility3.framework import renderers, interfaces
from volatility3.framework.configuration import requirements
from volatility3.framework.renderers import format_hints
from volatility3.plugins.windows import ssdt, driverscan

# built in Windows-components that trigger false positives
KNOWN_DRIVERS = ["ACPI_HAL", "PnpManager", "RAW", "WMIxWDM", "Win32k", "Fs_Rec"]


class DriverModule(interfaces.plugins.PluginInterface):
    """Determines if any loaded drivers were hidden by a rootkit"""

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
            requirements.PluginRequirement(
                name="ssdt", plugin=ssdt.SSDT, version=(1, 0, 0)
            ),
            requirements.PluginRequirement(
                name="driverscan", plugin=driverscan.DriverScan, version=(1, 0, 0)
            ),
        ]

    def _generator(self) -> Iterator[Tuple]:
        """
        Attempt to match each driver's start code address to a known kernel module
        A common rootkit technique is to register drivers from modules that are hidden,
        which allows us to detect the disconnect between a malicious driver and its hidden module.
        """
        kernel = self.context.modules[self.config["kernel"]]

        collection = ssdt.SSDT.build_module_collection(
            self.context, kernel.layer_name, kernel.symbol_table_name
        )

        for driver in driverscan.DriverScan.scan_drivers(
            self.context, kernel.layer_name, kernel.symbol_table_name
        ):
            # we do not care about actual symbol names, we just want to know if the driver points to a known module
            module_symbols = list(
                collection.get_module_symbols_by_absolute_location(driver.DriverStart)
            )
            if not module_symbols:
                (
                    driver_name,
                    service_key,
                    name,
                ) = driverscan.DriverScan.get_names_for_driver(driver)

                known_exception = driver_name in KNOWN_DRIVERS

                yield (
                    0,
                    (
                        format_hints.Hex(driver.vol.offset),
                        known_exception,
                        driver_name,
                        service_key,
                        name,
                    ),
                )

    def run(self) -> renderers.TreeGrid:
        return renderers.TreeGrid(
            [
                ("Offset", format_hints.Hex),
                ("Known Exception", bool),
                ("Driver Name", str),
                ("Service Key", str),
                ("Alternative Name", str),
            ],
            self._generator(),
        )
