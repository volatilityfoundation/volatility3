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
from typing import Callable, Iterable, List

import volatility.framework.interfaces.plugins as interfaces_plugins
from volatility.framework import renderers, interfaces, contexts, constants
from volatility.framework.automagic import mac
from volatility.framework.configuration import requirements
from volatility.framework.objects import utility

vollog = logging.getLogger(__name__)


class PsList(interfaces_plugins.PluginInterface):
    """Lists the processes present in a particular mac memory image"""

    @classmethod
    def get_requirements(cls):
        return [
            requirements.TranslationLayerRequirement(
                name = 'primary', description = 'Memory layer for the kernel', architectures = ["Intel32", "Intel64"]),
            requirements.SymbolTableRequirement(name = "darwin", description = "Mac kernel symbols")
        ]

    @classmethod
    def create_pid_filter(cls, pid_list: List[int] = None) -> Callable[[int], bool]:

        filter_func = lambda _: False
        # FIXME: mypy #4973 or #2608
        pid_list = pid_list or []
        filter_list = [x for x in pid_list if x is not None]
        if filter_list:

            def list_filter(x):
                return x.pid not in filter_list

            filter_func = list_filter
        return filter_func

    def _generator(self):
        for task in self.list_tasks(
                self.context,
                self.config['primary'],
                self.config['darwin'],
                filter_func = self.create_pid_filter([self.config.get('pid', None)])):
            pid = task.p_pid
            ppid = task.p_ppid
            name = utility.array_to_string(task.p_comm)
            yield (0, (pid, ppid, name))

    @classmethod
    def list_tasks(cls,
                   context: interfaces.context.ContextInterface,
                   layer_name: str,
                   darwin_symbols: str,
                   filter_func: Callable[[int], bool] = lambda _: False) -> \
            Iterable[interfaces.objects.ObjectInterface]:
        """Lists all the tasks in the primary layer"""

        mac.MacUtilities.aslr_mask_symbol_table(context, darwin_symbols, layer_name)

        kernel = contexts.Module(context, darwin_symbols, layer_name, 0)

        proc = kernel.object_from_symbol(symbol = "allproc").lh_first

        seen = {}
        while proc is not None and proc.vol.offset != 0:
            if proc.vol.offset in seen:
                vollog.log(logging.INFO, "Recursive process list detected (a result of non-atomic acquisition).")
                break
            else:
                seen[proc.vol.offset] = 1

            if not filter_func(proc):
                yield proc

            proc = proc.p_list.le_next.dereference()

    def run(self):
        return renderers.TreeGrid([("PID", int), ("PPID", int), ("COMM", str)], self._generator())
