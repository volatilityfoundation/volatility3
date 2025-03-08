# This file is Copyright 2022 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

import logging
from typing import Iterator, List, Set, Tuple

from volatility3.framework import constants, exceptions, interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.renderers import format_hints
from volatility3.framework.symbols.windows import extensions
from volatility3.plugins.windows import driverscan

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
                name="driverscan", plugin=driverscan.DriverScan, version=(2, 0, 0)
            ),
        ]

    def _generator(self) -> Iterator[Tuple]:
        # Scan the Layer for drivers
        for driver in driverscan.DriverScan.scan_drivers(
            self.context,
            self.config["kernel"],
        ):
            try:
                driver_name = driver.DriverName.get_string()
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
                for level, device_entry in self._traverse_device_tree(device, 1):
                    try:
                        device_name = device.get_device_name()
                    except (ValueError, exceptions.InvalidAddressException):
                        device_name = renderers.UnparsableValue()

                    try:
                        attached_driver_name = device.get_attached_driver_name()
                    except exceptions.InvalidAddressException:
                        attached_driver_name = renderers.UnparsableValue()

                    try:
                        device_type = device.get_device_type()
                    except exceptions.InvalidAddressException:
                        device_type = renderers.UnparsableValue()

                    yield level, (
                        format_hints.Hex(device_entry.vol.offset),
                        "DEV" if level == 1 else "ATT",
                        driver_name,
                        device_name,
                        attached_driver_name,
                        device_type,
                    )

    @classmethod
    def _traverse_device_tree(
        cls, device: extensions.DEVICE_OBJECT, level: int, seen: Set[int] = set()
    ) -> Iterator[Tuple[int, extensions.DEVICE_OBJECT]]:
        vollog.debug(f"Traversing device tree for device at {device.vol.offset:#x}")
        while device and device.vol.offset not in seen:
            seen.add(device.vol.offset)

            # Yield the first device and its level
            yield (
                level,
                device,
            )

            for attached in device.get_attached_devices():
                # Go depth-first through all of this device's child devices
                yield from cls._traverse_device_tree(attached, level + 1, seen)

            try:
                # Then move sideways to the next device in the current linked list
                device = device.NextDevice.dereference()
            except exceptions.InvalidAddressException:
                vollog.debug(
                    "Failed to dereference next driver in linked list, "
                    "may have reached end of list"
                )

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
