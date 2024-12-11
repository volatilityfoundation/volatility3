# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

from typing import Any, Callable, Iterable, List

from volatility3.framework import interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.objects import utility
from volatility3.framework.renderers import format_hints


class PsList(interfaces.plugins.PluginInterface):
    """Lists the processes present in a particular freebsd memory image."""

    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(
                name = "kernel",
                description = "Kernel module for the OS",
                architectures = ["Intel32", "Intel64"],
            ),
            requirements.ListRequirement(
                name = "pid",
                description = "Filter on specific process IDs",
                element_type = int,
                optional = True,
            ),
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
                return x.p_pid not in filter_list

            return filter_func
        else:
            return lambda _: False

    def _generator(self):
        for task in self.list_tasks(
                self.context,
                self.config["kernel"],
                filter_func = self.create_pid_filter(self.config.get("pid", None)),
        ):
            offset = format_hints.Hex(task.vol.offset)
            comm = utility.array_to_string(task.p_comm)
            pid = task.p_pid
            ppid = 0
            if task.p_pptr != 0:
                ppid = task.p_pptr.p_pid

            yield (0, (offset, pid, ppid, comm))

    @classmethod
    def list_tasks(
        cls,
        context: interfaces.context.ContextInterface,
        kernel_module_name: str,
        filter_func: Callable[[Any], bool] = lambda _: False,
    ) -> Iterable[interfaces.objects.ObjectInterface]:
        """Lists all the processes in the primary layer

        Args:
            context: The context to retrieve required elements (layers, symbol tables) from
            kernel_module_name: The name of the the kernel module on which to operate
            filter_func: A function which takes a process object and returns True if the process should be ignored/filtered

        Yields:
            Process objects
        """

        kernel = context.modules[kernel_module_name]

        proc = kernel.object_from_symbol(symbol_name = "allproc").lh_first.dereference()

        while proc.vol.offset != 0:
            if not filter_func(proc):
                yield proc
            proc = proc.p_list.le_next.dereference()

    def run(self):
        return renderers.TreeGrid(
            [
                ("OFFSET (V)", format_hints.Hex),
                ("PID", int),
                ("PPID", int),
                ("COMM", str),
            ],
            self._generator(),
        )
