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

import volatility.framework.interfaces.plugins as interfaces_plugins
import volatility.framework.interfaces.renderers as interfaces_renderers
import volatility.plugins.mac.pslist as pslist
from volatility.framework import constants
from volatility.framework import renderers
from volatility.framework.configuration import requirements
from volatility.framework.objects import utility
from volatility.framework.renderers import format_hints


class Malfind(interfaces_plugins.PluginInterface):
    """Lists process memory ranges that potentially contain injected code"""

    @classmethod
    def get_requirements(cls):
        return [
            requirements.TranslationLayerRequirement(
                name = 'primary', description = 'Memory layer for the kernel', architectures = ["Intel32", "Intel64"]),
            requirements.SymbolTableRequirement(name = "darwin", description = "Linux kernel symbols")
        ]

    def _list_injections(self, task):
        """Generate memory regions for a process that may contain
        injected code.
        """

        proc_layer_name = task.add_process_layer()
        if proc_layer_name is None:
            return

        proc_layer = self.context.memory[proc_layer_name]

        for vma in task.get_map_iter():
            if vma.is_suspicious(self.context, self.config['darwin']):
                data = proc_layer.read(vma.links.start, 64, pad = True)
                yield vma, data

    def _generator(self, tasks):
        # determine if we're on a 32 or 64 bit kernel
        if self.context.symbol_space.get_type(self.config["darwin"] + constants.BANG + "pointer").size == 4:
            is_32bit_arch = True
        else:
            is_32bit_arch = False

        for task in tasks:
            process_name = utility.array_to_string(task.p_comm)

            for vma, data in self._list_injections(task):
                if is_32bit_arch:
                    architecture = "intel"
                else:
                    architecture = "intel64"

                disasm = interfaces_renderers.Disassembly(data, vma.links.start, architecture)

                yield (0, (task.p_pid, process_name, format_hints.Hex(vma.links.start), format_hints.Hex(vma.links.end),
                           vma.get_perms(), format_hints.HexBytes(data), disasm))

    def run(self):
        filter_func = pslist.PsList.create_filter([self.config.get('pid', None)])

        return renderers.TreeGrid([("PID", int), ("Process", str), ("Start", format_hints.Hex),
                                   ("End", format_hints.Hex), ("Protection", str), ("Hexdump", format_hints.HexBytes),
                                   ("Disasm", interfaces_renderers.Disassembly)],
                                  self._generator(
                                      pslist.PsList.list_tasks(
                                          self.context,
                                          self.config['primary'],
                                          self.config['darwin'],
                                          filter_func = filter_func)))
