# This file is Copyright 2021 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

from volatility3.framework import interfaces, constants
from volatility3.framework import objects


class SUMMARY_DUMP(objects.StructType):
    def get_buffer(
        self, sub_type: str, count: int
    ) -> interfaces.objects.ObjectInterface:
        symbol_table_name = self.get_symbol_table_name()
        subtype = self._context.symbol_space.get_type(
            symbol_table_name + constants.BANG + sub_type
        )
        return self._context.object(
            object_type=symbol_table_name + constants.BANG + "array",
            layer_name=self.vol.layer_name,
            offset=self.BufferChar.vol.offset,
            count=count,
            subtype=subtype,
        )

    def get_buffer_char(self) -> interfaces.objects.ObjectInterface:
        return self.get_buffer(
            sub_type="unsigned char", count=(self.BitmapSize + 7) // 8
        )

    def get_buffer_long(self) -> interfaces.objects.ObjectInterface:
        return self.get_buffer(
            sub_type="unsigned long", count=(self.BitmapSize + 31) // 32
        )


class_types = {"_SUMMARY_DUMP": SUMMARY_DUMP}
