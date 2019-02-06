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

import datetime
from typing import Iterable

import volatility.framework.interfaces.plugins as plugins
from volatility.framework import renderers, interfaces
from volatility.framework.configuration import requirements
from volatility.framework.renderers import format_hints
from volatility.plugins import timeliner
import volatility.plugins.windows.poolscanner as poolscanner

class PsScan(plugins.PluginInterface, timeliner.TimeLinerInterface):
    """Scans for processes present in a particular windows memory image"""

    @classmethod
    def get_requirements(cls):
        return [
            requirements.TranslationLayerRequirement(
                name = 'primary', description = 'Memory layer for the kernel', architectures = ["Intel32", "Intel64"]),
            requirements.SymbolRequirement(name = "nt_symbols", description = "Windows kernel symbols"),
        ]

    @classmethod
    def scan_processes(cls,
                       context: interfaces.context.ContextInterface,
                       layer_name: str,
                       symbol_table: str) -> \
            Iterable[interfaces.objects.ObjectInterface]:
        """Scans for processes using the poolscanner module and constraints"""

        for result in poolscanner.PoolScanner.generate_pool_scan(context,
                                                                 layer_name,
                                                                 symbol_table):

            constraint, mem_object, _header = result
            if constraint.object_type == "Process":
                yield mem_object

    def _generator(self):
        for proc in self.scan_processes(
                self.context,
                self.config['primary'],
                self.config['nt_symbols']):

            yield (0, (proc.UniqueProcessId, proc.InheritedFromUniqueProcessId,
                       proc.ImageFileName.cast("string", max_length = proc.ImageFileName.vol.count, errors = 'replace'),
                       format_hints.Hex(proc.vol.offset), proc.ActiveThreads, proc.get_handle_count(), proc.get_session_id(),
                       proc.get_is_wow64(), proc.get_create_time(), proc.get_exit_time()))

    def generate_timeline(self):
        for row in self._generator():
            _depth, row_data = row
            description = "Process: {} ({})".format(row_data[2], row_data[3])
            yield (description, timeliner.TimeLinerType.CREATED, row_data[8])
            yield (description, timeliner.TimeLinerType.MODIFIED, row_data[9])

    def run(self):
        return renderers.TreeGrid([("PID", int), ("PPID", int), ("ImageFileName", str),
                                   ("Offset", format_hints.Hex), ("Threads", int),
                                   ("Handles", int), ("SessionId", int), ("Wow64", bool),
                                   ("CreateTime", datetime.datetime), ("ExitTime", datetime.datetime)],
                                  self._generator())
