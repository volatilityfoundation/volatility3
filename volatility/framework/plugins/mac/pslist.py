# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

import logging
from typing import Callable, Iterable, List, Dict

from volatility.framework import renderers, interfaces, contexts, exceptions
from volatility.framework.automagic import mac
from volatility.framework.configuration import requirements
from volatility.framework.objects import utility

vollog = logging.getLogger(__name__)


class PsList(interfaces.plugins.PluginInterface):
    """Lists the processes present in a particular mac memory image."""

    _version = (1, 0, 0)

    @classmethod
    def get_requirements(cls):
        return [
            requirements.TranslationLayerRequirement(name = 'primary',
                                                     description = 'Memory layer for the kernel',
                                                     architectures = ["Intel32", "Intel64"]),
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
        for task in self.list_tasks(self.context,
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
        """Lists all the processes in the primary layer.

        Args:
            context: The context to retrieve required elements (layers, symbol tables) from
            layer_name: The name of the layer on which to operate
            darwin_symbols: The name of the table containing the kernel symbols
            filter_func: A function which takes a process object and returns True if the process should be ignored/filtered

        Returns:
            The list of process objects from the processes linked list after filtering
        """

        kernel = contexts.Module(context, darwin_symbols, layer_name, 0)

        kernel_as = context.layers[layer_name]

        proc = kernel.object_from_symbol(symbol_name = "allproc").lh_first

        seen = {}  # type: Dict[int, int]
        while proc is not None and proc.vol.offset != 0:
            if proc.vol.offset in seen:
                vollog.log(logging.INFO, "Recursive process list detected (a result of non-atomic acquisition).")
                break
            else:
                seen[proc.vol.offset] = 1

            if not filter_func(proc) and kernel_as.is_valid(proc.vol.offset, proc.vol.size):
                yield proc

            try:
                proc = proc.p_list.le_next.dereference()
            except exceptions.InvalidAddressException:
                break

    def run(self):
        return renderers.TreeGrid([("PID", int), ("PPID", int), ("COMM", str)], self._generator())
