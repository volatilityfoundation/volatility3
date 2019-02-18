# This file was contributed to the Volatility Framework Version 2.
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

from typing import Callable, Iterable, List

import volatility.framework.interfaces.plugins as interfaces_plugins
from volatility.framework import renderers, interfaces, contexts
# from volatility.framework.automagic import linux #FreeBSD automagic not implemented
from volatility.framework.configuration import requirements
# from volatility.framework.objects import utility

class PsList(interfaces_plugins.PluginInterface):
    """Lists the processes present in a FreeBSD memory image"""

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        """Returns a list of requirement to satisfy executing the plugin"""
        return [requirements.TranslationLayerRequirement(
                    name = 'primary',
                    description = "Memory layer for the kernel",
                    architectures = ['Intel32', 'Intel64']),
                #requirements.SymbolTableRequirement(
                #    name = 'freebsd',  #TODO: is this right?
                #    description = "FreeBSD kernel Symbols")
            ]

    @classmethod
    def create_filter(cls, pid_list: List[int] = None) -> Callable[[int], bool]:
        # FIXME: mypy #4973 or #2608
        pid_list = pid_list or []
        filter_list = [x for x in pid_list if x is not None]
        if filter_list:
            def filter_func(x):
                return x not in filter_list

            return filter_func
        else:
            return lambda _: False

    @classmethod
    def list_tasks(cls,
                   context: interfaces.context.ContextInterface,
                   layer_name: str,
                   freebsd_symbols: str,
                   filter: Callable[[int],bool] = lambda _:False) \
                   -> Iterable[interfaces.objects.ObjectInterface]:
        """List all processes (tasks) in primary layer"""
        #TODO: aslr_mask_symbol_table?

        view = contexts.Module(context,
                               freebsd_symbols,
                               layer_name,
                               0,
                               absolute_symbol_addresses=True)

        # Symbol 'allproc' must be in profile
        proc = view.object(symbol_name = "allproc").lh_first

        #seen = {}
        while proc is not None and proc.vol.offset != 0:
            #TODO: Uncomment after testing
            #if proc.vol.offset in seen:
            #    vollog.log(logging.INFO, "Recursive process list detected (a result of non-atomic acquisition)")
            #    break
            #else:
            #    seen[proc.vol.offset] = 1

            # Generate and advance
            yield proc
            proc = proc.p_list.le_next.dereference()

    def _generator(self):
        """Produces all task after filtering"""
        for task in self.list_tasks(
                self.context,
                self.config['primary'],
                self.config['freebsd'],
                filter = self.create_filter([self.config.get('pid', None)])):
            pid = task.pid
            ppid = 0
            if task.parent:
                ppid = task.parent.pid
            name = utility.array_to_string(task.comm)
            yield (0, (pid, ppid, name))

    def run(self):
        """Entry point for plugin"""
        return renderers.TreeGrid([("PID", int), ("PPID", int), ("COMM", str)], self._generator())
