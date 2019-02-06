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
import ntpath
from typing import List

import volatility.framework.constants as constants
import volatility.framework.interfaces.plugins as interfaces_plugins
import volatility.plugins.windows.pslist as pslist
import volatility.plugins.windows.vadinfo as vadinfo
from volatility.framework import interfaces
from volatility.framework import renderers
from volatility.framework.configuration import requirements
from volatility.framework.objects import utility
from volatility.framework.symbols.windows.pe import PEIntermedSymbols

vollog = logging.getLogger(__name__)


class DllDump(interfaces_plugins.PluginInterface):
    """Dumps process memory ranges as DLLs"""

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        # Since we're calling the plugin, make sure we have the plugin's requirements
        return [requirements.TranslationLayerRequirement(name = 'primary',
                                                         description = 'Memory layer for the kernel',
                                                         architectures = ["Intel32", "Intel64"]),
                requirements.SymbolTableRequirement(name = "nt_symbols", description = "Windows kernel symbols"),
                # TODO: Convert this to a ListRequirement so that people can filter on sets of ranges
                requirements.IntRequirement(name = 'address',
                                            description = "Process virtual memory address to include " \
                                                          "(all other address ranges are excluded). This must be " \
                                                          "a base address, not an address within the desired range.",
                                            optional = True)]

    def _generator(self, procs):
        pe_table_name = PEIntermedSymbols.create(self.context, self.config_path, "windows", "pe")

        filter_func = lambda _: False
        if self.config.get('address', None) is not None:
            filter_func = lambda x: x.get_start() not in [self.config['address']]

        for proc in procs:
            process_name = utility.array_to_string(proc.ImageFileName)
            # TODO: what kind of exceptions could this raise and what should we do?
            proc_layer_name = proc.add_process_layer()

            for vad in vadinfo.VadInfo.list_vads(proc, filter_func = filter_func):

                # this parameter is inherited from the VadInfo plugin. if a user specifies
                # an address, then it bypasses the DLL identification heuristics
                if self.config.get("address", None) is None:

                    # rather than relying on the PEB for DLLs, which can be swapped,
                    # it requires special handling on wow64 processes, and its
                    # unreliable from an integrity standpoint, let's use the VADs instead
                    protection_string = vad.get_protection(
                        vadinfo.VadInfo.protect_values(self.context, self.config['primary'], self.config['nt_symbols']),
                        vadinfo.winnt_protections)

                    # DLLs are write copy...
                    if protection_string != "PAGE_EXECUTE_WRITECOPY":
                        continue

                    # DLLs have mapped files...
                    if isinstance(vad.get_file_name(), interfaces.renderers.BaseAbsentValue):
                        continue

                try:
                    filedata = interfaces_plugins.FileInterface("pid.{0}.{1}.{2:#x}.dmp".format(
                        proc.UniqueProcessId, ntpath.basename(vad.get_file_name()), vad.get_start()))

                    dos_header = self.context.object(
                        pe_table_name + constants.BANG + "_IMAGE_DOS_HEADER",
                        offset = vad.get_start(),
                        layer_name = proc_layer_name)

                    for offset, data in dos_header.reconstruct():
                        filedata.data.seek(offset)
                        filedata.data.write(data)

                    self.produce_file(filedata)
                    result_text = "Stored {}".format(filedata.preferred_filename)
                except Exception:
                    result_text = "Unable to dump PE at {0:#x}".format(vad.get_start())

                yield (0, (proc.UniqueProcessId, process_name, result_text))

    def run(self):
        filter_func = pslist.PsList.create_filter([self.config.get('pid', None)])

        return renderers.TreeGrid([("PID", int), ("Process", str), ("Result", str)],
                                  self._generator(
                                      pslist.PsList.list_processes(
                                          context = self.context,
                                          layer_name = self.config['primary'],
                                          symbol_table = self.config['nt_symbols'],
                                          filter_func = filter_func)))
