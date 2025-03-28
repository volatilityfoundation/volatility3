import logging
from typing import Dict

from volatility3.framework import exceptions, objects
from volatility3.framework.symbols.windows.extensions import pool

vollog = logging.getLogger(__name__)


class _SHUTDOWN_PACKET(objects.StructType, pool.ExecutiveObject):
    """Class for _SHUTDOWN_PACKET objects found in IoSh pools.

    This class serves as a base class for all pooled shutdown callback packets.

    It exposes a function which sanity-checks structure members.
    """

    def is_valid(self) -> bool:
        """
        Perform some checks.
        """
        try:
            if not (
                self.Entry.Flink.is_readable()
                and self.Entry.Blink.is_readable()
                and self.DeviceObject.is_readable()
            ):
                vollog.debug(
                    f"Callback obj 0x{self.vol.offset:x} invalid due to unreadable structure members"
                )
                return False

        except exceptions.InvalidAddressException:
            vollog.debug(
                f"callback obj 0x{self.vol.offset:x} invalid due to invalid address access"
            )
            return False

        return True

    def is_parseable(self, type_map: Dict[int, str]) -> bool:
        """
        Determines whether or not this `_SHUTDOWN_PACKET` callback can be reliably parsed.
        Requires a `type_map` that maps NT executive object type indices to string representations.
        This type map can be acquired via the `handles.Handles.get_type_map` classmethod.
        """
        if not self.is_valid():
            return False

        try:

            device = self.DeviceObject
            if not device or not (device.DriverObject.DriverStart % 0x1000 == 0):
                vollog.debug(
                    f"callback obj 0x{self.vol.offset:x} invalid due to invalid device object"
                )
                return False

            header = device.get_object_header()
            object_type = header.get_object_type(type_map)
            is_valid = object_type == "Device"
            if not is_valid:
                vollog.debug(
                    f"Callback obj 0x{self.vol.offset:x} invalid due to invalid device type: wanted 'Device', found '{object_type}'"
                )
            return is_valid
        except exceptions.InvalidAddressException:
            vollog.debug(
                f"callback obj 0x{self.vol.offset:x} invalid due to invalid address access"
            )
            return False
        except ValueError:
            vollog.debug(
                f"Could not get object type for object at 0x{self.vol.offset:x}"
            )
            return False


class_types_x86 = {"_SHUTDOWN_PACKET": _SHUTDOWN_PACKET}
