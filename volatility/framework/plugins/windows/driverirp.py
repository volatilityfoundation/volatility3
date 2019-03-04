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

import volatility.framework.interfaces.plugins as plugins
from volatility.framework import renderers, exceptions
from volatility.framework.configuration import requirements
from volatility.framework.renderers import format_hints
from volatility.plugins.windows.driverscan import DriverScan
from volatility.plugins.windows import ssdt
from volatility.framework import constants

MAJOR_FUNCTIONS = [
    'IRP_MJ_CREATE',
    'IRP_MJ_CREATE_NAMED_PIPE',
    'IRP_MJ_CLOSE',
    'IRP_MJ_READ',
    'IRP_MJ_WRITE',
    'IRP_MJ_QUERY_INFORMATION',
    'IRP_MJ_SET_INFORMATION',
    'IRP_MJ_QUERY_EA',
    'IRP_MJ_SET_EA',
    'IRP_MJ_FLUSH_BUFFERS',
    'IRP_MJ_QUERY_VOLUME_INFORMATION',
    'IRP_MJ_SET_VOLUME_INFORMATION',
    'IRP_MJ_DIRECTORY_CONTROL',
    'IRP_MJ_FILE_SYSTEM_CONTROL',
    'IRP_MJ_DEVICE_CONTROL',
    'IRP_MJ_INTERNAL_DEVICE_CONTROL',
    'IRP_MJ_SHUTDOWN',
    'IRP_MJ_LOCK_CONTROL',
    'IRP_MJ_CLEANUP',
    'IRP_MJ_CREATE_MAILSLOT',
    'IRP_MJ_QUERY_SECURITY',
    'IRP_MJ_SET_SECURITY',
    'IRP_MJ_POWER',
    'IRP_MJ_SYSTEM_CONTROL',
    'IRP_MJ_DEVICE_CHANGE',
    'IRP_MJ_QUERY_QUOTA',
    'IRP_MJ_SET_QUOTA',
    'IRP_MJ_PNP'
]

class DriverIrp(plugins.PluginInterface):
    """List IRPs for drivers in a particular windows memory image"""

    @classmethod
    def get_requirements(cls):
        return [
            requirements.TranslationLayerRequirement(
                name = 'primary', description = 'Memory layer for the kernel', architectures = ["Intel32", "Intel64"]),
            requirements.SymbolTableRequirement(name = "nt_symbols", description = "Windows kernel symbols"),
        ]

    def _generator(self):

        collection = ssdt.SSDT.build_module_collection(self.context,
                                                       self.config['primary'],
                                                       self.config['nt_symbols'])


        for driver in DriverScan.scan_drivers(self.context,
                                              self.config['primary'],
                                              self.config['nt_symbols']):

            try:
                driver_name = driver.get_driver_name()
            except exceptions.InvalidAddressException:
                driver_name = renderers.NotApplicableValue()

            for i, address in enumerate(driver.MajorFunction):
                module_symbols = collection.get_module_symbols_by_absolute_location(address)

                for module_name, symbol_generator in module_symbols:
                    symbols_found = False

                    for symbol in symbol_generator:
                        symbols_found = True
                        yield (0, (format_hints.Hex(driver.vol.offset),
                                   driver_name,
                                   MAJOR_FUNCTIONS[i],
                                   format_hints.Hex(address),
                                   module_name,
                                   symbol.split(constants.BANG)[1]))

                    if not symbols_found:
                        yield (0, (format_hints.Hex(driver.vol.offset),
                                   driver_name,
                                   MAJOR_FUNCTIONS[i],
                                   format_hints.Hex(address),
                                   module_name,
                                   renderers.NotAvailableValue()))

    def run(self):
        return renderers.TreeGrid([("Offset", format_hints.Hex),
                                   ("Driver Name", str),
                                   ("IRP", str),
                                   ("Address", format_hints.Hex),
                                   ("Module", str),
                                   ("Symbol", str),],
                                  self._generator())
