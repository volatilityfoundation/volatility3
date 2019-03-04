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

import volatility.framework.interfaces.plugins as plugins
from volatility.framework import renderers, interfaces, exceptions
from volatility.framework.configuration import requirements
from volatility.framework.renderers import format_hints
import volatility.plugins.windows.poolscanner as poolscanner

class DriverScan(plugins.PluginInterface):
    """Scans for drivers present in a particular windows memory image"""

    @classmethod
    def get_requirements(cls):
        return [
            requirements.TranslationLayerRequirement(
                name = 'primary', description = 'Memory layer for the kernel', architectures = ["Intel32", "Intel64"]),
            requirements.SymbolTableRequirement(name = "nt_symbols", description = "Windows kernel symbols"),
        ]

    @classmethod
    def scan_drivers(cls,
                     context: interfaces.context.ContextInterface,
                     layer_name: str,
                     symbol_table: str) -> \
            Iterable[interfaces.objects.ObjectInterface]:
        """Scans for drivers using the poolscanner module and constraints"""

        constraints = poolscanner.PoolScanner.builtin_constraints(symbol_table,
                                                                  [b'Dri\xf6', b'Driv'])

        for result in poolscanner.PoolScanner.generate_pool_scan(context,
                                                                 layer_name,
                                                                 symbol_table,
                                                                 constraints):

            _constraint, mem_object, _header = result
            yield mem_object

    def _generator(self):
        for driver in self.scan_drivers(self.context,
                                        self.config['primary'],
                                        self.config['nt_symbols']):

            try:
                driver_name = driver.get_driver_name()
            except exceptions.InvalidAddressException:
                driver_name = renderers.NotApplicableValue()

            try:
                service_key = driver.DriverExtension.ServiceKeyName.String
            except exceptions.InvalidAddressException:
                service_key = renderers.NotApplicableValue()

            try:
                name = driver.DriverName.String
            except exceptions.InvalidAddressException:
                name = renderers.NotApplicableValue()

            yield (0, (format_hints.Hex(driver.vol.offset),
                       format_hints.Hex(driver.DriverStart),
                       format_hints.Hex(driver.DriverSize),
                       service_key,
                       driver_name,
                       name))

    def run(self):
        return renderers.TreeGrid([("Offset", format_hints.Hex),
                                   ("Start", format_hints.Hex),
                                   ("Size", format_hints.Hex),
                                   ("Service Key", str),
                                   ("Driver Name", str),
                                   ("Name", str)],
                                  self._generator())
