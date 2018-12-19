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

from volatility.framework.objects import utility
from volatility.plugins.linux import pslist


class PsTree(pslist.PsList):
    """Plugin for listing processes in a tree based on their parent process ID """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._processes = {}
        self._levels = {}
        self._children = {}

    def find_level(self, pid):
        """Finds how deep the pid is in the processes list"""
        seen = set([])
        seen.add(pid)
        level = 0
        proc = self._processes.get(pid, None)
        while proc is not None and proc.parent != 0 and proc.parent.pid not in seen:
            ppid = int(proc.parent.pid)

            child_list = self._children.get(ppid, set([]))
            child_list.add(proc.pid)
            self._children[ppid] = child_list
            proc = self._processes.get(ppid, None)
            level += 1
        self._levels[pid] = level

    def _generator(self):
        """Generates the """
        for proc in self.list_tasks(self.context, self.config['primary'], self.config['vmlinux']):
            self._processes[proc.pid] = proc

        # Build the child/level maps
        for pid in self._processes:
            self.find_level(pid)

        def yield_processes(pid):
            proc = self._processes[pid]
            row = (proc.pid, proc.parent.pid, utility.array_to_string(proc.comm))

            yield (self._levels[pid] - 1, row)
            for child_pid in self._children.get(pid, []):
                yield from yield_processes(child_pid)

        for pid in self._levels:
            if self._levels[pid] == 1:
                yield from yield_processes(pid)
