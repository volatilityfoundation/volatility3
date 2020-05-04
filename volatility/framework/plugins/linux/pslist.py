# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

from typing import Callable, Iterable, List, Any

from volatility.framework import renderers, interfaces, contexts
from volatility.framework.automagic import linux
from volatility.framework.configuration import requirements
from volatility.framework.objects import utility


class PsList(interfaces.plugins.PluginInterface):
    """Lists the processes present in a particular linux memory image."""

    _version = (1, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.TranslationLayerRequirement(name = 'primary',
                                                     description = 'Memory layer for the kernel',
                                                     architectures = ["Intel32", "Intel64"]),
            requirements.SymbolTableRequirement(name = "vmlinux", description = "Linux kernel symbols")
        ]

    @classmethod
    def create_pid_filter(cls, pid_list: List[int] = None) -> Callable[[Any], bool]:
        """Constructs a filter function for process IDs.

        Args:
            pid_list: List of process IDs that are acceptable (or None if all are acceptable)

        Returns:
            Function which, when provided a process object, returns True if the process is to be filtered out of the list
        """
        # FIXME: mypy #4973 or #2608
        pid_list = pid_list or []
        filter_list = [x for x in pid_list if x is not None]
        if filter_list:

            def filter_func(x):
                return x.pid not in filter_list

            return filter_func
        else:
            return lambda _: False

    def _generator(self):
        for task in self.list_tasks(self.context,
                                    self.config['primary'],
                                    self.config['vmlinux'],
                                    filter_func = self.create_pid_filter([self.config.get('pid', None)])):
            pid = task.pid
            ppid = 0
            if task.parent:
                ppid = task.parent.pid
            name = utility.array_to_string(task.comm)
            yield (0, (pid, ppid, name))

    @classmethod
    def list_tasks(
            cls,
            context: interfaces.context.ContextInterface,
            layer_name: str,
            vmlinux_symbols: str,
            filter_func: Callable[[int], bool] = lambda _: False) -> Iterable[interfaces.objects.ObjectInterface]:
        """Lists all the tasks in the primary layer.

        Args:
            context: The context to retrieve required elements (layers, symbol tables) from
            layer_name: The name of the layer on which to operate
            vmlinux_symbols: The name of the table containing the kernel symbols

        Yields:
            Process objects
        """
        vmlinux = contexts.Module(context, vmlinux_symbols, layer_name, 0)

        init_task = vmlinux.object_from_symbol(symbol_name = "init_task")

        for task in init_task.tasks:
            if not filter_func(task):
                yield task

    def run(self):
        return renderers.TreeGrid([("PID", int), ("PPID", int), ("COMM", str)], self._generator())
