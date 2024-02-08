# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

from volatility3.framework import objects, interfaces
from volatility3.framework import exceptions
from volatility3.framework.symbols.wrappers import Flags
from volatility3.framework import renderers
from typing import Union


class SERVICE_RECORD(objects.StructType):
    """A service record structure."""

    def is_valid(self) -> bool:
        """Determine if the structure is valid."""
        if self.Order < 0 or self.Order > 0xFFFF:
            return False

        try:
            _ = self.State.description
            _ = self.Start.description
        except ValueError:
            return False

        return True

    def get_pid(self) -> Union[int, interfaces.renderers.BaseAbsentValue]:
        """Return the pid of the process, if any."""
        if (
            self.State.description != "SERVICE_RUNNING"
            or "PROCESS" not in self.get_type()
        ):
            return renderers.NotApplicableValue()

        try:
            return self.ServiceProcess.ProcessId
        except exceptions.InvalidAddressException:
            return renderers.UnreadableValue()

    def get_binary(self) -> Union[str, interfaces.renderers.BaseAbsentValue]:
        """Returns the binary associated with the service."""
        if self.State.description != "SERVICE_RUNNING":
            return renderers.NotApplicableValue()

        # depending on whether the service is for a process
        # or kernel driver, the binary path is stored differently
        try:
            if "PROCESS" in self.get_type():
                return self.ServiceProcess.BinaryPath.dereference().cast(
                    "string", encoding="utf-16", errors="replace", max_length=512
                )
            else:
                return self.DriverName.dereference().cast(
                    "string", encoding="utf-16", errors="replace", max_length=512
                )
        except exceptions.InvalidAddressException:
            return renderers.UnreadableValue()

    def get_name(self) -> Union[str, interfaces.renderers.BaseAbsentValue]:
        """Returns the service name."""
        try:
            return self.ServiceName.dereference().cast(
                "string", encoding="utf-16", errors="replace", max_length=512
            )
        except exceptions.InvalidAddressException:
            return renderers.UnreadableValue()

    def get_display(self) -> Union[str, interfaces.renderers.BaseAbsentValue]:
        """Returns the service display."""
        try:
            return self.DisplayName.dereference().cast(
                "string", encoding="utf-16", errors="replace", max_length=512
            )
        except exceptions.InvalidAddressException:
            return renderers.UnreadableValue()

    def get_type(self) -> str:
        """Returns the binary types."""

        SERVICE_TYPE_FLAGS = {
            "SERVICE_KERNEL_DRIVER": 1,
            "SERVICE_FILE_SYSTEM_DRIVER": 2,
            "SERVICE_ADAPTOR": 4,
            "SERVICE_RECOGNIZER_DRIVER": 8,
            "SERVICE_WIN32_OWN_PROCESS": 16,
            "SERVICE_WIN32_SHARE_PROCESS": 32,
            "SERVICE_INTERACTIVE_PROCESS": 256,
        }

        type_flags = Flags(choices=SERVICE_TYPE_FLAGS)
        return "|".join(type_flags(self.Type))

    def traverse(self):
        """Generator that enumerates other services."""

        try:
            if hasattr(self, "PrevEntry"):
                yield self
                # make sure we dereference these pointers, or the
                # is_valid() checks will apply to the pointer and
                # not the _SERVICE_RECORD object as intended.
                rec = self.PrevEntry
                while rec and rec.is_valid():
                    yield rec
                    rec = rec.PrevEntry
            else:
                rec = self
                while rec and rec.is_valid():
                    yield rec
                    rec = rec.ServiceList.Blink.dereference()
        except exceptions.InvalidAddressException:
            return None


class SERVICE_HEADER(objects.StructType):
    """A service header structure."""

    def is_valid(self) -> bool:
        """Determine if the structure is valid."""
        try:
            return self.ServiceRecord.is_valid()
        except exceptions.InvalidAddressException:
            return False


class_types = {"_SERVICE_RECORD": SERVICE_RECORD, "_SERVICE_HEADER": SERVICE_HEADER}
