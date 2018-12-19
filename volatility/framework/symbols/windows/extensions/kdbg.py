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

from volatility.framework import constants
from volatility.framework import objects


class _KDDEBUGGER_DATA64(objects.Struct):

    def get_build_lab(self):
        """Returns the NT build lab string from the KDBG"""

        layer_name = self.vol.layer_name
        symbol_table_name = self.get_symbol_table().name

        return self._context.object(
            symbol_table_name + constants.BANG + "string",
            layer_name = layer_name,
            offset = self.NtBuildLab,
            max_length = 32,
            errors = "replace")

    def get_csdversion(self):
        """Returns the CSDVersion as an integer (i.e. Service Pack number)"""

        layer_name = self.vol.layer_name
        symbol_table_name = self.get_symbol_table().name

        csdresult = self._context.object(
            symbol_table_name + constants.BANG + "unsigned long", layer_name = layer_name, offset = self.CmNtCSDVersion)

        return (csdresult >> 8) & 0xffffffff
