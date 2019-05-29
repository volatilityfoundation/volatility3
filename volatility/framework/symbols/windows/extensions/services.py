# This file was contributed to the Volatility Framework Version 3.
# Copyright (C) 2018 Volatility Foundation.
#
# THE LICENSED WORK IS PROVIDED UNDER THE TERMS OF THE Volatility Contributors
# Public License V1.0("LICENSE") AS FIRST COMPLETED BY: Volatility Foundation,
# Inc. ANY USE, PUBLIC DISPLAY, PUBLIC PERFORMANCE, REPRODUCTION OR DISTRIBUTION
# OF, OR PREPARATION OF SUBSEQUENT WORKS, DERIVATIVE WORKS OR DERIVED WORKS BASED
# ON, THE LICENSED WORK CONSTITUTES RECIPIENT'S ACCEPTANCE OF THIS LICENSE AND ITS
# TERMS, WHETHER OR NOT SUCH RECIPIENT READS THE TERMS OF THE LICENSE. "LICENSED
# WORK,” “RECIPIENT" AND “DISTRIBUTOR" ARE DEFINED IN THE LICENSE. A COPY OF THE
# LICENSE IS LOCATED IN THE TEXT FILE ENTITLED "LICENSE.txt" ACCOMPANYING THE
# CONTENTS OF THIS FILE. IF A COPY OF THE LICENSE DOES NOT ACCOMPANY THIS FILE, A
# COPY OF THE LICENSE MAY ALSO BE OBTAINED AT THE FOLLOWING WEB SITE:
# https://www.volatilityfoundation.org/license/vcpl_v1.0
#
# Software distributed under the License is distributed on an "AS IS" basis,
# WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License for the
# specific language governing rights and limitations under the License.
#

from volatility.framework import objects, interfaces
from volatility.framework import exceptions
from volatility.framework.symbols.wrappers import Flags
from volatility.framework import renderers
from typing import Union

class _SERVICE_RECORD(objects.Struct):
    """A service record structure"""

    def is_valid(self) -> bool:
        """Determine if the structure is valid"""
        if self.Order < 0 or self.Order > 0xFFFF:
            return False

        try:
            _ = self.State.description
            _ = self.Start.description
        except ValueError:
            return False

        return True

    def get_pid(self) -> Union[int, interfaces.renderers.BaseAbsentValue]:
        """Return the pid of the process, if any"""
        if self.State.description != "SERVICE_RUNNING" or "PROCESS" not in self.get_type():
            return renderers.NotApplicableValue()

        try:
            return self.ServiceProcess.ProcessId
        except exceptions.InvalidAddressException:
            return renderers.UnreadableValue()

    def get_binary(self) -> Union[str, interfaces.renderers.BaseAbsentValue]:
        """Returns the binary associated with the service"""
        if self.State.description != "SERVICE_RUNNING":
            return renderers.NotApplicableValue()

        # depending on whether the service is for a process
        # or kernel driver, the binary path is stored differently
        try:
            if "PROCESS" in self.get_type():
                return self.ServiceProcess.BinaryPath.dereference().cast("string",
                                                                         encoding = "utf-16",
                                                                         errors = "replace",
                                                                         max_length = 512)
            else:
                return self.DriverName.dereference().cast("string",
                                                          encoding = "utf-16",
                                                          errors = "replace",
                                                          max_length = 512)
        except exceptions.InvalidAddressException:
            return renderers.UnreadableValue()

    def get_name(self) -> Union[str, interfaces.renderers.BaseAbsentValue]:
        """Returns the service name"""
        try:
            return self.ServiceName.dereference().cast("string",
                                                       encoding = "utf-16",
                                                       errors = "replace",
                                                       max_length = 512)
        except exceptions.InvalidAddressException:
            return renderers.UnreadableValue()

    def get_display(self) -> Union[str, interfaces.renderers.BaseAbsentValue]:
        """Returns the service display"""
        try:
            return self.DisplayName.dereference().cast("string",
                                                       encoding = "utf-16",
                                                       errors = "replace",
                                                       max_length = 512)
        except exceptions.InvalidAddressException:
            return renderers.UnreadableValue()

    def get_type(self) -> str:
        """Returns the binary types"""

        SERVICE_TYPE_FLAGS = {
            'SERVICE_KERNEL_DRIVER': 1,
            'SERVICE_FILE_SYSTEM_DRIVER': 2,
            'SERVICE_ADAPTOR': 4,
            'SERVICE_RECOGNIZER_DRIVER': 8,
            'SERVICE_WIN32_OWN_PROCESS': 16,
            'SERVICE_WIN32_SHARE_PROCESS': 32,
            'SERVICE_INTERACTIVE_PROCESS': 256
        }

        type_flags = Flags(choices = SERVICE_TYPE_FLAGS)
        return "|".join(type_flags(self.Type))

    def traverse(self):
        """Generator that enumerates other services"""

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
            raise StopIteration

class _SERVICE_HEADER(objects.Struct):
    """A service header structure"""

    def is_valid(self) -> bool:
        """Determine if the structure is valid"""
        try:
            return self.ServiceRecord.is_valid()
        except exceptions.InvalidAddressException:
            return False
