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

from volatility.framework import exceptions
from volatility.framework import objects
from volatility.framework.objects import utility
from volatility.framework.renderers import conversion


class hist_entry(objects.Struct):

    def is_valid(self):
        try:
            cmd = self.get_command()
            ts = utility.array_to_string(self.timestamp.dereference())
        except exceptions.PagedInvalidAddressException:
            return False

        if not cmd or len(cmd) == 0:
            return False

        if not ts or len(ts) == 0:
            return False

        # At this point in time, the epoc integer size will
        # never be less than 10 characters, and the stamp is
        # always preceded by a pound/hash character.
        if len(ts) < 10 or str(ts)[0] != "#":
            return False

        # The final check is to make sure the entire string
        # is composed of numbers. Try to convert to an int.
        try:
            int(str(ts)[1:])
        except ValueError:
            return False

        return True

    def get_time_as_integer(self):
        # Get the string and remove the leading "#" from the timestamp
        time_string = utility.array_to_string(self.timestamp.dereference())[1:]
        # Convert the string into an integer (number of seconds)
        return int(time_string)

    def get_time_object(self):
        nsecs = self.get_time_as_integer()
        # Build a timestamp object from the integer
        return conversion.unixtime_to_datetime(nsecs)

    def get_command(self):
        return utility.array_to_string(self.line.dereference())
