# This file is Copyright 2021 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

from volatility3.framework import interfaces, constants
from volatility3.framework import objects
import array


class SUMMARY_DUMP(objects.StructType):
    def get_buffer_char(self) -> bytes:
        return self._context.layers[self.vol.layer_name].read(
            self.BufferChar.vol.offset, (self.BitmapSize + 7) // 8
        )

    def get_buffer_long(self) -> list:
        unsigned_long_array = array.array("I")
        unsigned_long_array.frombytes(self.get_buffer_char())

        return list(unsigned_long_array)


class_types_shared = {"_SUMMARY_DUMP": SUMMARY_DUMP}
class_types_unshared = {"_SUMMARY_DUMP_OLD": SUMMARY_DUMP}
