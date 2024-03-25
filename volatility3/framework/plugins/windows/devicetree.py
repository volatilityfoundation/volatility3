# This file is Copyright 2022 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

import logging

from typing import Iterator, List, Tuple

from volatility3.framework import constants, renderers, exceptions, interfaces
from volatility3.framework.configuration import requirements
from volatility3.framework.renderers import format_hints
from volatility3.plugins.windows import driverscan

DEVICE_CODES = {
    0x00000027: "FILE_DEVICE_8042_PORT",
    0x00000032: "FILE_DEVICE_ACPI",
    0x00000029: "FILE_DEVICE_BATTERY",
    0x00000001: "FILE_DEVICE_BEEP",
    0x0000002A: "FILE_DEVICE_BUS_EXTENDER",
    0x00000002: "FILE_DEVICE_CD_ROM",
    0x00000003: "FILE_DEVICE_CD_ROM_FILE_SYSTEM",
    0x00000030: "FILE_DEVICE_CHANGER",
    0x00000004: "FILE_DEVICE_CONTROLLER",
    0x00000005: "FILE_DEVICE_DATALINK",
    0x00000006: "FILE_DEVICE_DFS",
    0x00000035: "FILE_DEVICE_DFS_FILE_SYSTEM",
    0x00000036: "FILE_DEVICE_DFS_VOLUME",
    0x00000007: "FILE_DEVICE_DISK",
    0x00000008: "FILE_DEVICE_DISK_FILE_SYSTEM",
    0x00000033: "FILE_DEVICE_DVD",
    0x00000009: "FILE_DEVICE_FILE_SYSTEM",
    0x0000003A: "FILE_DEVICE_FIPS",
    0x00000034: "FILE_DEVICE_FULLSCREEN_VIDEO",
    0x0000000A: "FILE_DEVICE_INPORT_PORT",
    0x0000000B: "FILE_DEVICE_KEYBOARD",
    0x0000002F: "FILE_DEVICE_KS",
    0x00000039: "FILE_DEVICE_KSEC",
    0x0000000C: "FILE_DEVICE_MAILSLOT",
    0x0000002D: "FILE_DEVICE_MASS_STORAGE",
    0x0000000D: "FILE_DEVICE_MIDI_IN",
    0x0000000E: "FILE_DEVICE_MIDI_OUT",
    0x0000002B: "FILE_DEVICE_MODEM",
    0x0000000F: "FILE_DEVICE_MOUSE",
    0x00000010: "FILE_DEVICE_MULTI_UNC_PROVIDER",
    0x00000011: "FILE_DEVICE_NAMED_PIPE",
    0x00000012: "FILE_DEVICE_NETWORK",
    0x00000013: "FILE_DEVICE_NETWORK_BROWSER",
    0x00000014: "FILE_DEVICE_NETWORK_FILE_SYSTEM",
    0x00000028: "FILE_DEVICE_NETWORK_REDIRECTOR",
    0x00000015: "FILE_DEVICE_NULL",
    0x00000016: "FILE_DEVICE_PARALLEL_PORT",
    0x00000017: "FILE_DEVICE_PHYSICAL_NETCARD",
    0x00000018: "FILE_DEVICE_PRINTER",
    0x00000019: "FILE_DEVICE_SCANNER",
    0x0000001C: "FILE_DEVICE_SCREEN",
    0x00000037: "FILE_DEVICE_SERENUM",
    0x0000001A: "FILE_DEVICE_SERIAL_MOUSE_PORT",
    0x0000001B: "FILE_DEVICE_SERIAL_PORT",
    0x00000031: "FILE_DEVICE_SMARTCARD",
    0x0000002E: "FILE_DEVICE_SMB",
    0x0000001D: "FILE_DEVICE_SOUND",
    0x0000001E: "FILE_DEVICE_STREAMS",
    0x0000001F: "FILE_DEVICE_TAPE",
    0x00000020: "FILE_DEVICE_TAPE_FILE_SYSTEM",
    0x00000038: "FILE_DEVICE_TERMSRV",
    0x00000021: "FILE_DEVICE_TRANSPORT",
    0x00000022: "FILE_DEVICE_UNKNOWN",
    0x0000002C: "FILE_DEVICE_VDM",
    0x00000023: "FILE_DEVICE_VIDEO",
    0x00000024: "FILE_DEVICE_VIRTUAL_DISK",
    0x00000025: "FILE_DEVICE_WAVE_IN",
    0x00000026: "FILE_DEVICE_WAVE_OUT",
}

vollog = logging.getLogger(__name__)


class DeviceTree(interfaces.plugins.PluginInterface):
    """Listing tree based on drivers and attached devices in a particular windows memory image."""

    _required_framework_version = (2, 0, 3)
    _version = (1, 0, 1)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Windows kernel",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.PluginRequirement(
                name="driverscan", plugin=driverscan.DriverScan, version=(1, 0, 0)
            ),
        ]

    def _generator(self) -> Iterator[Tuple]:
        kernel = self.context.modules[self.config["kernel"]]

        # Scan the Layer for drivers
        for driver in driverscan.DriverScan.scan_drivers(
            self.context, kernel.layer_name, kernel.symbol_table_name
        ):
            try:
                try:
                    driver_name = driver.get_driver_name()
                except (ValueError, exceptions.InvalidAddressException):
                    vollog.log(
                        constants.LOGLEVEL_VVVV,
                        f"Failed to get Driver name : {driver.vol.offset:x}",
                    )
                    driver_name = renderers.UnparsableValue()

                yield (
                    0,
                    (
                        format_hints.Hex(driver.vol.offset),
                        "DRV",
                        driver_name,
                        renderers.NotApplicableValue(),
                        renderers.NotApplicableValue(),
                        renderers.NotApplicableValue(),
                    ),
                )

                # Scan to get the device information of driver.
                for device in driver.get_devices():
                    try:
                        device_name = device.get_device_name()
                    except (ValueError, exceptions.InvalidAddressException):
                        vollog.log(
                            constants.LOGLEVEL_VVVV,
                            f"Failed to get Device name : {device.vol.offset:x}",
                        )
                        device_name = renderers.UnparsableValue()

                    device_type = DEVICE_CODES.get(device.DeviceType, "UNKNOWN")

                    yield (
                        1,
                        (
                            format_hints.Hex(driver.vol.offset),
                            "DEV",
                            driver_name,
                            device_name,
                            renderers.NotApplicableValue(),
                            device_type,
                        ),
                    )

                    # Scan to get the attached devices information of device.
                    for level, attached_device in enumerate(
                        device.get_attached_devices(), start=2
                    ):
                        try:
                            device_name = attached_device.get_device_name()
                        except (ValueError, exceptions.InvalidAddressException):
                            vollog.log(
                                constants.LOGLEVEL_VVVV,
                                f"Failed to get Attached Device Name: {attached_device.vol.offset:x}",
                            )
                            device_name = renderers.UnparsableValue()

                        attached_device_driver_name = (
                            attached_device.DriverObject.DriverName.get_string()
                        )
                        attached_device_type = DEVICE_CODES.get(
                            attached_device.DeviceType, "UNKNOWN"
                        )

                        yield (
                            level,
                            (
                                format_hints.Hex(driver.vol.offset),
                                "ATT",
                                driver_name,
                                device_name,
                                attached_device_driver_name,
                                attached_device_type,
                            ),
                        )

            except exceptions.InvalidAddressException:
                vollog.log(
                    constants.LOGLEVEL_VVVV,
                    f"Invalid address identified in drivers and devices: {driver.vol.offset:x}",
                )
                continue

    def run(self) -> renderers.TreeGrid:
        return renderers.TreeGrid(
            [
                ("Offset", format_hints.Hex),
                ("Type", str),
                ("DriverName", str),
                ("DeviceName", str),
                ("DriverNameOfAttDevice", str),
                ("DeviceType", str),
            ],
            self._generator(),
        )
