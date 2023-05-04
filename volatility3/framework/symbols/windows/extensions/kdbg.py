# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

from volatility3.framework import constants
from volatility3.framework import objects


class KDDEBUGGER_DATA64(objects.StructType):
    def get_build_lab(self):
        """Returns the NT build lab string from the KDBG."""

        layer_name = self.vol.layer_name
        symbol_table_name = self.get_symbol_table_name()

        return self._context.object(
            symbol_table_name + constants.BANG + "string",
            layer_name=layer_name,
            offset=self.NtBuildLab,
            max_length=32,
            errors="replace",
        )

    def get_csdversion(self):
        """Returns the CSDVersion as an integer (i.e. Service Pack number)"""

        layer_name = self.vol.layer_name
        symbol_table_name = self.get_symbol_table_name()

        csdresult = self._context.object(
            symbol_table_name + constants.BANG + "unsigned long",
            layer_name=layer_name,
            offset=self.CmNtCSDVersion,
        )

        return (csdresult >> 8) & 0xFFFFFFFF


class_types = {"_KDDEBUGGER_DATA64": KDDEBUGGER_DATA64}
