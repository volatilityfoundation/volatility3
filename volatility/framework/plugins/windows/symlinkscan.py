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

from typing import Iterable
import datetime
import volatility.framework.interfaces.plugins as plugins
from volatility.framework import renderers, interfaces, exceptions
from volatility.framework.configuration import requirements
from volatility.framework.renderers import format_hints
import volatility.plugins.windows.poolscanner as poolscanner
from volatility.plugins import timeliner

class SymlinkScan(plugins.PluginInterface, timeliner.TimeLinerInterface):
    """Scans for links present in a particular windows memory image"""

    @classmethod
    def get_requirements(cls):
        return [
            requirements.TranslationLayerRequirement(
                name = 'primary', description = 'Memory layer for the kernel', architectures = ["Intel32", "Intel64"]),
            requirements.SymbolTableRequirement(name = "nt_symbols", description = "Windows kernel symbols"),
        ]

    @classmethod
    def scan_symlinks(cls,
                     context: interfaces.context.ContextInterface,
                     layer_name: str,
                     symbol_table: str) -> \
            Iterable[interfaces.objects.ObjectInterface]:
        """Scans for links using the poolscanner module and constraints"""

        constraints = poolscanner.PoolScanner.builtin_constraints(symbol_table, [b'Sym\xe2', b'Symb'])

        for result in poolscanner.PoolScanner.generate_pool_scan(context, layer_name, symbol_table, constraints):

            _constraint, mem_object, _header = result
            yield mem_object

    def _generator(self):
        for link in self.scan_symlinks(self.context, self.config['primary'], self.config['nt_symbols']):

            try:
                from_name = link.get_link_name()
            except exceptions.InvalidAddressException:
                continue

            try:
                to_name = link.LinkTarget.String
            except exceptions.InvalidAddressException:
                continue

            yield (0, (format_hints.Hex(link.vol.offset), link.get_create_time(), from_name, to_name))

    def generate_timeline(self):
        for row in self._generator():
            _depth, row_data = row
            description = "Symlink: {} -> {}".format(row_data[2], row_data[3])
            yield (description, timeliner.TimeLinerType.CREATED, row_data[1])

    def run(self):
        return renderers.TreeGrid([
            ("Offset", format_hints.Hex),
            ("CreateTime", datetime.datetime),
            ("From Name", str),
            ("To Name", str),
        ], self._generator())
