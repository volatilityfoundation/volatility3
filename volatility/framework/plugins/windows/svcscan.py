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

import logging
from typing import Any, List
from volatility.framework import interfaces, renderers, constants, symbols
from volatility.framework.layers import scanners
from volatility.framework.configuration import requirements
from volatility.framework.renderers import format_hints
from volatility.framework.plugins.windows import poolscanner
from volatility.framework.plugins.windows import vadyarascan
from volatility.plugins.windows import pslist
from volatility.framework.symbols.windows.services import ServicesIntermedSymbols

vollog = logging.getLogger(__name__)

class SvcScan(interfaces.plugins.PluginInterface):
    """Scans for windows services"""

    is_vista_or_later = poolscanner.os_distinguisher(
        version_check=lambda x: x >= (6, 0), fallback_checks=[("KdCopyDataBlock", None, True)])

    is_windows_xp = poolscanner.os_distinguisher(
        version_check=lambda x: (5, 1) <= x < (5, 2), fallback_checks=[("KdCopyDataBlock", None, False),
                                                                       ("_HANDLE_TABLE", "HandleCount", True)])

    is_xp_or_2003 = poolscanner.os_distinguisher(
        version_check=lambda x: (5, 1) <= x < (6, 0), fallback_checks=[("KdCopyDataBlock", None, False),
                                                                       ("_HANDLE_TABLE", "HandleCount", True)])

    is_win10_up_to_15063 = poolscanner.os_distinguisher(
        version_check=lambda x: (10, 0) <= x < (10, 0, 16299), fallback_checks=[("ObHeaderCookie", None, True),
                                                                                ("_HANDLE_TABLE", "HandleCount", False),
                                                                                ("ObHeaderCookie", None, True)])

    is_win10_16299_or_later = poolscanner.os_distinguisher(
        version_check=lambda x: x >= (10, 0, 16299), fallback_checks=[("ObHeaderCookie", None, True),
                                                                      ("_HANDLE_TABLE", "HandleCount", False),
                                                                      ("ObHeaderCookie", None, True)])

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        # Since we're calling the plugin, make sure we have the plugin's requirements
        return [
            requirements.TranslationLayerRequirement(
                name = 'primary', description = 'Memory layer for the kernel', architectures = ["Intel32", "Intel64"]),
            requirements.SymbolTableRequirement(name = "nt_symbols", description = "Windows kernel symbols")
        ] + pslist.PsList.list_processes_filter_requirements

    @staticmethod
    def get_record_tuple(service_record: Any):
        return (format_hints.Hex(service_record.vol.offset),
                service_record.Order,
                service_record.get_pid(),
                service_record.Start.description,
                service_record.State.description,
                service_record.get_type(),
                service_record.get_name(),
                service_record.get_display(),
                service_record.get_binary())

    @staticmethod
    def create_service_table(context: interfaces.context.ContextInterface,
                             symbol_table: str,
                             config_path: str) -> str:

        native_types = context.symbol_space[symbol_table].natives
        is_64bit = symbols.symbol_table_is_64bit(context, symbol_table)

        if SvcScan.is_windows_xp(context = context, symbol_table = symbol_table) and not is_64bit:
            symbol_filename = "services-xp-x86"
        elif SvcScan.is_xp_or_2003(context = context, symbol_table = symbol_table) and is_64bit:
            symbol_filename = "services-xp-2003-x64"
        elif poolscanner.PoolScanner.is_windows_8_or_later(context = context, symbol_table = symbol_table) and is_64bit:
            symbol_filename = "services-win8-x64"
        elif poolscanner.PoolScanner.is_windows_8_or_later(context = context, symbol_table = symbol_table) and not is_64bit:
            symbol_filename = "services-win8-x86"
        elif SvcScan.is_win10_up_to_15063(context = context, symbol_table = symbol_table) and is_64bit:
            symbol_filename = "services-win10-15063-x64"
        elif SvcScan.is_win10_up_to_15063(context = context, symbol_table = symbol_table) and not is_64bit:
            symbol_filename = "services-win10-15063-x86"
        elif SvcScan.is_win10_16299_or_later(context = context, symbol_table = symbol_table) and is_64bit:
            symbol_filename = "services-win10-16299-x64"
        elif SvcScan.is_win10_16299_or_later(context = context, symbol_table = symbol_table) and not is_64bit:
            symbol_filename = "services-win10-16299-x86"
        elif SvcScan.is_vista_or_later(context = context, symbol_table = symbol_table) and is_64bit:
            symbol_filename = "services-vista-x64"
        elif SvcScan.is_vista_or_later(context = context, symbol_table = symbol_table) and not is_64bit:
            symbol_filename = "services-vista-x86"
        else:
            raise NotImplementedError("This version of Windows is not supported!")

        print(symbol_filename)
        return ServicesIntermedSymbols.create(context,
                                              config_path,
                                              "windows",
                                              symbol_filename,
                                              native_types = native_types)

    def _generator(self):

        service_table_name = self.create_service_table(self.context,
                                                       self.config["nt_symbols"],
                                                       self.config_path)

        relative_tag_offset = self.context.symbol_space.get_type(
            service_table_name + constants.BANG + "_SERVICE_RECORD").relative_child_offset("Tag")

        filter_func = pslist.PsList.create_name_filter(["services.exe"])

        is_vista_or_later = SvcScan.is_vista_or_later(context = self.context,
                                                      symbol_table = self.config["nt_symbols"])

        if is_vista_or_later:
            service_tag = b"serH"
        else:
            service_tag = b"sErv"

        seen = []

        for task in pslist.PsList.list_processes(context = self.context,
                                                 layer_name = self.config['primary'],
                                                 symbol_table = self.config['nt_symbols'],
                                                 filter_func = filter_func):

            proc_layer_name = task.add_process_layer()
            layer = self.context.memory[proc_layer_name]

            for offset in layer.scan(context = self.context,
                                     scanner = scanners.BytesScanner(needle = service_tag),
                                     sections = vadyarascan.VadYaraScan.get_vad_maps(task)):

                if not is_vista_or_later:
                    service_record = self.context.object(service_table_name + constants.BANG + "_SERVICE_RECORD",
                                                         offset = offset - relative_tag_offset,
                                                         layer_name = proc_layer_name)

                    if not service_record.is_valid():
                        continue

                    yield (0, self.get_record_tuple(service_record))
                else:
                    service_header = self.context.object(service_table_name + constants.BANG + "_SERVICE_HEADER",
                                                         offset = offset,
                                                         layer_name = proc_layer_name)

                    if not service_header.is_valid():
                        continue

                    # since we walk the s-list backwards, if we've seen
                    # an object, then we've also seen all objects that
                    # exist before it, thus we can break at that time.
                    for service_record in service_header.ServiceRecord.traverse():
                        if service_record in seen:
                            break
                        seen.append(service_record)
                        yield (0, self.get_record_tuple(service_record))

    def run(self):
        return renderers.TreeGrid([('Offset', format_hints.Hex),
                                   ('Order', int),
                                   ('Pid', int),
                                   ('Start', str),
                                   ('State', str),
                                   ('Type', str),
                                   ('Name', str),
                                   ('Display', str),
                                   ('Binary', str),
                                   ], self._generator())
