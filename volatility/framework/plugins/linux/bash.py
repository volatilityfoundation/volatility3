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
"""A module containing a collection of plugins that produce data
typically found in Linux's /proc file system.
"""

import datetime
import struct
from typing import List

from volatility.framework import constants, renderers, symbols, interfaces
from volatility.framework.configuration import requirements
from volatility.framework.interfaces import plugins
from volatility.framework.layers import scanners
from volatility.framework.objects import utility
from volatility.framework.symbols.linux.bash import BashIntermedSymbols
from volatility.plugins import timeliner
from volatility.plugins.linux import pslist


class Bash(plugins.PluginInterface, timeliner.TimeLinerInterface):
    """Recovers bash command history from memory"""

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.TranslationLayerRequirement(
                name = 'primary', description = 'Kernel Address Space', architectures = ["Intel32", "Intel64"]),
            requirements.SymbolRequirement(name = "vmlinux", description = "Linux Kernel")
        ]

    def _generator(self, tasks):
        is_32bit = not symbols.symbol_table_is_64bit(self.context, self.config["vmlinux"])
        if is_32bit:
            pack_format = "I"
            bash_json_file = "bash32"
        else:
            pack_format = "Q"
            bash_json_file = "bash64"

        bash_table_name = BashIntermedSymbols.create(self.context, self.config_path, "linux", bash_json_file)

        ts_offset = self.context.symbol_space.get_type(bash_table_name + constants.BANG +
                                                       "hist_entry").relative_child_offset("timestamp")

        for task in tasks:
            task_name = utility.array_to_string(task.comm)
            if task_name not in ["bash", "sh", "dash"]:
                continue

            proc_layer_name = task.add_process_layer()
            if not proc_layer_name:
                continue

            proc_layer = self.context.memory[proc_layer_name]

            bang_addrs = []

            # find '#' values on the heap
            for address in proc_layer.scan(
                    self.context,
                    scanners.BytesScanner(b"#"),
                    sections = task.get_process_memory_sections(heap_only = True)):
                bang_addrs.append(struct.pack(pack_format, address))

            history_entries = []

            for address, _ in proc_layer.scan(
                    self.context,
                    scanners.MultiStringScanner(bang_addrs),
                    sections = task.get_process_memory_sections(heap_only = True)):
                hist = self.context.object(
                    bash_table_name + constants.BANG + "hist_entry",
                    offset = address - ts_offset,
                    layer_name = proc_layer_name)

                if hist.is_valid():
                    history_entries.append(hist)

            for hist in sorted(history_entries, key = lambda x: x.get_time_as_integer()):
                yield (0, (task.pid, task_name, hist.get_time_object(), hist.get_command()))

    def run(self):
        filter_func = pslist.PsList.create_filter([self.config.get('pid', None)])

        plugin = pslist.PsList.list_tasks

        return renderers.TreeGrid(
            [("PID", int), ("Process", str), ("CommandTime", datetime.datetime), ("Command", str)],
            self._generator(plugin(self.context, self.config['primary'], self.config['vmlinux'], filter = filter_func)))

    def generate_timeline(self):
        filter_func = pslist.PsList.create_filter([self.config.get('pid', None)])

        plugin = pslist.PsList.list_tasks

        for row in self._generator(
                plugin(self.context, self.config['primary'], self.config['vmlinux'], filter = filter_func)):
            _depth, row_data = row
            description = "{} ({}): \"{}\"".format(row_data[0], row_data[1], row_data[3])
            yield (description, timeliner.TimeLinerType.CREATED, row_data[2])
