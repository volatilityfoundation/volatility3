import logging
from typing import Callable, Iterable, List

import volatility.framework.interfaces.plugins as interfaces_plugins
from volatility.framework import renderers, interfaces
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
                name = 'primary', description = 'Kernel Address Space', architectures = ["Intel32", "Intel64"]),
            requirements.SymbolRequirement(name = "darwin", description = "Mac Kernel")
        ]

    @classmethod
    def create_filter(cls, pid_list: List[int] = None) -> Callable[[int], bool]:

        def nullfilter():
            return False

        filter_func = nullfilter
        # FIXME: mypy #4973 or #2608
        pid_list = pid_list or []
        filter_list = [x for x in pid_list if x is not None]
        if filter_list:

            def list_filter(x):
                return x not in filter_list

            filter_func = list_filter
        return filter_func

    def _generator(self):
        for task in self.list_tasks(
                self.context,
                self.config['primary'],
                self.config['darwin'],
                filter = self.create_filter([self.config.get('pid', None)])):
            pid = task.p_pid
            ppid = task.p_ppid
            name = utility.array_to_string(task.p_comm)
            yield (0, (pid, ppid, name))

    @classmethod
    def list_tasks(cls,
                   context: interfaces.context.ContextInterface,
                   layer_name: str,
                   mac_symbols: str,
                   filter: Callable[[int], bool] = lambda _: False) -> \
            Iterable[interfaces.objects.ObjectInterface]:
        """Lists all the tasks in the primary layer"""

        aslr_shift = mac.MacUtilities.find_aslr(context, mac_symbols, layer_name)
        darwin = context.module(mac_symbols, layer_name, aslr_shift)
        proc = darwin.object(symbol_name = "allproc").lh_first

        seen = {}
        while proc is not None and proc.vol.offset != 0:
            if proc.vol.offset in seen:
                vollog.log(logging.INFO, "Recursive process list detected (a result of non-atomic acquisition).")
                break
            else:
                seen[proc.vol.offset] = 1

            yield proc

            proc = proc.p_list.le_next.dereference()

    def run(self):
        return renderers.TreeGrid([("PID", int), ("PPID", int), ("COMM", str)], self._generator())
