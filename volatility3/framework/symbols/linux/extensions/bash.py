# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

from volatility3.framework import exceptions
from volatility3.framework import objects
from volatility3.framework.objects import utility
from volatility3.framework.renderers import conversion


class hist_entry(objects.StructType):
    def is_valid(self):
        try:
            cmd = self.get_command()
            ts = utility.array_to_string(self.timestamp.dereference())
        except exceptions.InvalidAddressException:
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
