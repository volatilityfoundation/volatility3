import logging

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
                return False

            device = self.DeviceObject
            if not device or not (device.DriverObject.DriverStart % 0x1000 == 0):
                vollog.debug(
                    f"callback obj 0x{self.vol.offset:x} invalid due to invalid device object"
                )
                return False

        except exceptions.InvalidAddressException:
            vollog.debug(
                f"callback obj 0x{self.vol.offset:x} invalid due to invalid address access"
            )
            return False

        try:
            header = device.get_object_header()
            valid = header.NameInfo.Name == "Device"
            return valid
        except ValueError:
            vollog.debug(f"Could not get NameInfo for object at 0x{self.vol.offset:x}")
            return False


class_types_x86 = {"_SHUTDOWN_PACKET": _SHUTDOWN_PACKET}
