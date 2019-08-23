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
from typing import List

import volatility.framework.constants as constants
import volatility.framework.exceptions as exceptions
import volatility.framework.interfaces.plugins as interfaces_plugins
import volatility.framework.renderers as renderers
import volatility.plugins.windows.pslist as pslist
from volatility.framework import interfaces
from volatility.framework.configuration import requirements
from volatility.framework.objects import utility
from volatility.framework.symbols.windows.extensions import pe

from volatility.framework.symbols import intermed

vollog = logging.getLogger(__name__)


class ProcDump(interfaces_plugins.PluginInterface):
    """Dumps process executable images"""

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        # Since we're calling the plugin, make sure we have the plugin's requirements
        return [
            requirements.TranslationLayerRequirement(
                name = 'primary', description = 'Memory layer for the kernel', architectures = ["Intel32", "Intel64"]),
            requirements.SymbolTableRequirement(name = "nt_symbols", description = "Windows kernel symbols"),
            requirements.IntRequirement(
                name = 'pid', description = "Process ID to include (all other processes are excluded)", optional = True)
        ]

    def _generator(self, procs):

        pe_table_name = intermed.IntermediateSymbolTable.create(
            self.context, self.config_path, "windows", "pe", class_types = pe.class_types)

        for proc in procs:
            process_name = utility.array_to_string(proc.ImageFileName)
            # TODO: what kind of exceptions could this raise and what should we do?
            proc_layer_name = proc.add_process_layer()

            try:
                peb = self._context.object(
                    self.config["nt_symbols"] + constants.BANG + "_PEB",
                    layer_name = proc_layer_name,
                    offset = proc.Peb)

                dos_header = self.context.object(
                    pe_table_name + constants.BANG + "_IMAGE_DOS_HEADER",
                    offset = peb.ImageBaseAddress,
                    layer_name = proc_layer_name)

                filedata = interfaces_plugins.FileInterface("pid.{0}.{1:#x}.dmp".format(
                    proc.UniqueProcessId, peb.ImageBaseAddress))

                for offset, data in dos_header.reconstruct():
                    filedata.data.seek(offset)
                    filedata.data.write(data)

                self.produce_file(filedata)
                result_text = "Stored {}".format(filedata.preferred_filename)

            except ValueError:
                result_text = "PE parsing error"

            except exceptions.SwappedInvalidAddressException as exp:
                result_text = "Required memory at {0:#x} is inaccessible (swapped)".format(exp.invalid_address)

            except exceptions.PagedInvalidAddressException as exp:
                result_text = "Required memory at {0:#x} is not valid (process exited?)".format(exp.invalid_address)

            yield (0, (proc.UniqueProcessId, process_name, result_text))

    def run(self):
        filter_func = pslist.PsList.create_pid_filter([self.config.get('pid', None)])

        return renderers.TreeGrid([("PID", int), ("Process", str), ("Result", str)],
                                  self._generator(
                                      pslist.PsList.list_processes(
                                          context = self.context,
                                          layer_name = self.config['primary'],
                                          symbol_table = self.config['nt_symbols'],
                                          filter_func = filter_func)))
