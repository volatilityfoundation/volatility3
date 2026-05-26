# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

import logging

from volatility3.framework import constants
from volatility3.framework import renderers, exceptions, interfaces
from volatility3.framework.configuration import requirements
from volatility3.framework.renderers import format_hints
from volatility3.plugins.windows import ssdt, driverscan, modules

vollog = logging.getLogger(__name__)

MAJOR_FUNCTIONS = [
    "IRP_MJ_CREATE",
    "IRP_MJ_CREATE_NAMED_PIPE",
    "IRP_MJ_CLOSE",
    "IRP_MJ_READ",
    "IRP_MJ_WRITE",
    "IRP_MJ_QUERY_INFORMATION",
    "IRP_MJ_SET_INFORMATION",
    "IRP_MJ_QUERY_EA",
    "IRP_MJ_SET_EA",
    "IRP_MJ_FLUSH_BUFFERS",
    "IRP_MJ_QUERY_VOLUME_INFORMATION",
    "IRP_MJ_SET_VOLUME_INFORMATION",
    "IRP_MJ_DIRECTORY_CONTROL",
    "IRP_MJ_FILE_SYSTEM_CONTROL",
    "IRP_MJ_DEVICE_CONTROL",
    "IRP_MJ_INTERNAL_DEVICE_CONTROL",
    "IRP_MJ_SHUTDOWN",
    "IRP_MJ_LOCK_CONTROL",
    "IRP_MJ_CLEANUP",
    "IRP_MJ_CREATE_MAILSLOT",
    "IRP_MJ_QUERY_SECURITY",
    "IRP_MJ_SET_SECURITY",
    "IRP_MJ_POWER",
    "IRP_MJ_SYSTEM_CONTROL",
    "IRP_MJ_DEVICE_CHANGE",
    "IRP_MJ_QUERY_QUOTA",
    "IRP_MJ_SET_QUOTA",
    "IRP_MJ_PNP",
]


class DriverIrp(interfaces.plugins.PluginInterface):
    """List IRPs for drivers in a particular windows memory image."""

    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 0)

    @classmethod
    def get_requirements(cls):
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Windows kernel",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.VersionRequirement(
                name="ssdt", component=ssdt.SSDT, version=(2, 0, 0)
            ),
            requirements.VersionRequirement(
                name="driverscan", component=driverscan.DriverScan, version=(2, 0, 0)
            ),
            requirements.VersionRequirement(
                name="modules", component=modules.Modules, version=(3, 0, 0)
            ),
        ]

    def _generator(self):
        collection = ssdt.SSDT.build_module_collection(
            context=self.context,
            kernel_module_name=self.config["kernel"],
        )

        kernel_space_start = modules.Modules.get_kernel_space_start(
            context=self.context,
            module_name=self.config["kernel"],
        )

        for driver in driverscan.DriverScan.scan_drivers(
            self.context,
            self.config["kernel"],
        ):
            try:
                driver_name = driver.get_driver_name()
            except (ValueError, exceptions.InvalidAddressException):
                driver_name = renderers.NotApplicableValue()

            for i in range(len(driver.MajorFunction)):
                try:
                    irp_handler = driver.MajorFunction[i]
                except exceptions.InvalidAddressException:
                    vollog.debug(
                        f"Failed to get IRP handler entry at index {i} for driver at {driver.vol.offset:#x}"
                    )
                    continue

                # smear
                if irp_handler < kernel_space_start:
                    continue

                module_symbols = collection.get_module_symbols_by_absolute_location(
                    irp_handler
                )

                module_found = False

                for module_name, symbol_generator in module_symbols:
                    module_found = True
                    symbols_found = False

                    for symbol in symbol_generator:
                        symbols_found = True
                        yield (
                            0,
                            (
                                format_hints.Hex(driver.vol.offset),
                                driver_name,
                                MAJOR_FUNCTIONS[i],
                                format_hints.Hex(irp_handler),
                                module_name,
                                symbol.split(constants.BANG)[1],
                            ),
                        )

                    if not symbols_found:
                        yield (
                            0,
                            (
                                format_hints.Hex(driver.vol.offset),
                                driver_name,
                                MAJOR_FUNCTIONS[i],
                                format_hints.Hex(irp_handler),
                                module_name,
                                renderers.NotAvailableValue(),
                            ),
                        )

                if not module_found:
                    yield (
                        0,
                        (
                            format_hints.Hex(driver.vol.offset),
                            driver_name,
                            MAJOR_FUNCTIONS[i],
                            format_hints.Hex(irp_handler),
                            renderers.NotAvailableValue(),
                            renderers.NotAvailableValue(),
                        ),
                    )

    def run(self):
        return renderers.TreeGrid(
            [
                ("Offset", format_hints.Hex),
                ("Driver Name", str),
                ("IRP", str),
                ("Address", format_hints.Hex),
                ("Module", str),
                ("Symbol", str),
            ],
            self._generator(),
        )
