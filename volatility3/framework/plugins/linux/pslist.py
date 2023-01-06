# This file is Copyright 2021 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
from typing import Callable, Iterable, List, Any, Tuple

from volatility3.framework import renderers, interfaces
from volatility3.framework.configuration import requirements
from volatility3.framework.objects import utility
from volatility3.framework.renderers import format_hints


class PsList(interfaces.plugins.PluginInterface):
    """Lists the processes present in a particular linux memory image."""

    _required_framework_version = (2, 0, 0)

    _version = (2, 1, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Linux kernel",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.ListRequirement(
                name="pid",
                description="Filter on specific process IDs",
                element_type=int,
                optional=True,
            ),
            requirements.BooleanRequirement(
                name="threads",
                description="Include user threads",
                optional=True,
                default=False,
            ),
            requirements.BooleanRequirement(
                name="decorate_comm",
                description="Show `user threads` comm in curly brackets, and `kernel threads` comm in square brackets",
                optional=True,
                default=False,
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
                return x.pid not in filter_list

            return filter_func
        else:
            return lambda _: False

    def _get_task_fields(
        self, task: interfaces.objects.ObjectInterface, decorate_comm: bool = False
    ) -> Tuple[int, int, int, str]:
        """Extract the fields needed for the final output

        Args:
            task: A task object from where to get the fields.
            decorate_comm: If True, it decorates the comm string of
                            - User threads: in curly brackets,
                            - Kernel threads: in square brackets
                           Defaults to False.
        Returns:
            A tuple with the fields to show in the plugin output.
        """
        pid = task.tgid
        tid = task.pid
        ppid = task.parent.tgid if task.parent else 0
        name = utility.array_to_string(task.comm)
        if decorate_comm:
            if task.is_kernel_thread:
                name = f"[{name}]"
            elif task.is_user_thread:
                name = f"{{{name}}}"

        task_fields = (format_hints.Hex(task.vol.offset), pid, tid, ppid, name)
        return task_fields

    def _generator(
        self,
        pid_filter: Callable[[Any], bool],
        include_threads: bool = False,
        decorate_comm: bool = False,
    ):
        """Generates the tasks list.

        Args:
            pid_filter: A function which takes a process object and returns True if the process should be ignored/filtered
            include_threads: If True, the output will also show the user threads
                             If False, only the thread group leaders will be shown
                             Defaults to False.
            decorate_comm: If True, it decorates the comm string of
                            - User threads: in curly brackets,
                            - Kernel threads: in square brackets
                           Defaults to False.
        Yields:
            Each rows
        """
        for task in self.list_tasks(
            self.context, self.config["kernel"], pid_filter, include_threads
        ):
            row = self._get_task_fields(task, decorate_comm)
            yield (0, row)

    @classmethod
    def list_tasks(
        cls,
        context: interfaces.context.ContextInterface,
        vmlinux_module_name: str,
        filter_func: Callable[[int], bool] = lambda _: False,
        include_threads: bool = False,
    ) -> Iterable[interfaces.objects.ObjectInterface]:
        """Lists all the tasks in the primary layer.

        Args:
            context: The context to retrieve required elements (layers, symbol tables) from
            vmlinux_module_name: The name of the kernel module on which to operate
            filter_func: A function which takes a process object and returns True if the process should be ignored/filtered
            include_threads: If True, it will also return user threads.
        Yields:
            Task objects
        """
        vmlinux = context.modules[vmlinux_module_name]

        init_task = vmlinux.object_from_symbol(symbol_name="init_task")

        # Note that the init_task itself is not yielded, since "ps" also never shows it.
        for task in init_task.tasks:
            if filter_func(task):
                continue

            yield task

            if include_threads:
                yield from task.get_threads()

    def run(self):
        pids = self.config.get("pid")
        include_threads = self.config.get("threads")
        decorate_comm = self.config.get("decorate_comm")
        filter_func = self.create_pid_filter(pids)

        columns = [
            ("OFFSET (V)", format_hints.Hex),
            ("PID", int),
            ("TID", int),
            ("PPID", int),
            ("COMM", str),
        ]
        return renderers.TreeGrid(
            columns, self._generator(filter_func, include_threads, decorate_comm)
        )
