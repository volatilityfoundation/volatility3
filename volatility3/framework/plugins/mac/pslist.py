# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

import datetime
import logging
from typing import Callable, Dict, Iterable, List, Optional

from volatility3.framework import exceptions, interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.objects import utility
from volatility3.framework.renderers import format_hints
from volatility3.framework.symbols import mac

vollog = logging.getLogger(__name__)


class PsList(interfaces.plugins.PluginInterface):
    """Lists the processes present in a particular mac memory image."""

    _required_framework_version = (2, 0, 0)
    _version = (3, 0, 0)
    pslist_methods = ["tasks", "allproc", "process_group", "sessions", "pid_hash_table"]

    @classmethod
    def get_requirements(cls):
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Kernel module for the OS",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.VersionRequirement(
                name="macutils", component=mac.MacUtilities, version=(1, 1, 0)
            ),
            requirements.ChoiceRequirement(
                name="pslist_method",
                description="Method to determine for processes",
                choices=cls.pslist_methods,
                default=cls.pslist_methods[0],
                optional=True,
            ),
            requirements.ListRequirement(
                name="pid",
                description="Filter on specific process IDs",
                element_type=int,
                optional=True,
            ),
        ]

    @classmethod
    def get_list_tasks(cls, method: str) -> Callable[
        [interfaces.context.ContextInterface, str, Callable[[int], bool]],
        Iterable[interfaces.objects.ObjectInterface],
    ]:
        """Returns the list_tasks method based on the selector

        Args:
            method: Must be one of the available methods in get_task_choices

        Returns:
            list_tasks method for listing tasks
        """
        # Ensure method is one of the suitable choices
        if method not in cls.pslist_methods:
            method = cls.pslist_methods[0]

        if method == "allproc":
            list_tasks = cls.list_tasks_allproc
        elif method == "tasks":
            list_tasks = cls.list_tasks_tasks
        elif method == "process_group":
            list_tasks = cls.list_tasks_process_group
        elif method == "sessions":
            list_tasks = cls.list_tasks_sessions
        elif method == "pid_hash_table":
            list_tasks = cls.list_tasks_pid_hash_table
        else:
            raise ValueError("Impossible method choice chosen")
        vollog.debug(f"Using method {method}")

        return list_tasks

    @classmethod
    def create_pid_filter(
        cls, pid_list: Optional[List[int]] = None
    ) -> Callable[[int], bool]:
        def filter_func(_):
            return False

        # FIXME: mypy #4973 or #2608
        pid_list = pid_list or []
        filter_list = [x for x in pid_list if x is not None]
        if filter_list:

            def list_filter(x):
                return x.p_pid not in filter_list

            filter_func = list_filter
        return filter_func

    def _generator(self):
        list_tasks = self.get_list_tasks(
            self.config.get("pslist_method", self.pslist_methods[0])
        )

        for task in list_tasks(
            self.context,
            self.config["kernel"],
            filter_func=self.create_pid_filter(self.config.get("pid", None)),
        ):
            offset = format_hints.Hex(task.vol.offset)
            name = utility.array_to_string(task.p_comm)
            pid = task.p_pid
            uid = task.p_uid
            gid = task.p_gid
            start_time_seconds = task.p_start.tv_sec
            start_time_microseconds = task.p_start.tv_usec
            start_time = datetime.datetime.fromtimestamp(
                start_time_seconds + start_time_microseconds / 1e6
            )

            ppid = task.p_ppid

            yield (0, (offset, name, pid, uid, gid, start_time, ppid))

    @classmethod
    def list_tasks_allproc(
        cls,
        context: interfaces.context.ContextInterface,
        kernel_module_name: str,
        filter_func: Callable[[int], bool] = lambda _: False,
    ) -> Iterable[interfaces.objects.ObjectInterface]:
        """Lists all the processes in the primary layer based on the allproc method

        Args:
            context: The context to retrieve required elements (layers, symbol tables) from
            kernel_module_name: The name of the kernel module on which to operate
            filter_func: A function which takes a process object and returns True if the process should be ignored/filtered

        Returns:
            The list of process objects from the processes linked list after filtering
        """

        kernel = context.modules[kernel_module_name]

        kernel_layer = context.layers[kernel.layer_name]

        proc = kernel.object_from_symbol(symbol_name="allproc").lh_first

        seen: Dict[int, int] = {}
        while proc is not None and proc.vol.offset != 0:
            if proc.vol.offset in seen:
                vollog.log(
                    logging.INFO,
                    "Recursive process list detected (a result of non-atomic acquisition).",
                )
                break
            else:
                seen[proc.vol.offset] = 1

            if kernel_layer.is_valid(
                proc.vol.offset, proc.vol.size
            ) and not filter_func(proc):
                yield proc

            try:
                proc = proc.p_list.le_next.dereference()
            except exceptions.InvalidAddressException:
                break

    @classmethod
    def list_tasks_tasks(
        cls,
        context: interfaces.context.ContextInterface,
        kernel_module_name: str,
        filter_func: Callable[[int], bool] = lambda _: False,
    ) -> Iterable[interfaces.objects.ObjectInterface]:
        """Lists all the tasks in the primary layer based on the tasks queue

        Args:
            context: The context to retrieve required elements (layers, symbol tables) from
            kernel_module_name: The name of the kernel module on which to operate
            filter_func: A function which takes a task object and returns True if the task should be ignored/filtered

        Returns:
            The list of task objects from the `layer_name` layer's `tasks` list after filtering
        """
        kernel = context.modules[kernel_module_name]

        kernel_layer = context.layers[kernel.layer_name]

        queue_entry = kernel.object_from_symbol(symbol_name="tasks")

        seen: Dict[int, int] = {}
        for task in queue_entry.walk_list(queue_entry, "tasks", "task"):
            if task.vol.offset in seen:
                vollog.log(
                    logging.INFO,
                    "Recursive process list detected (a result of non-atomic acquisition).",
                )
                break
            else:
                seen[task.vol.offset] = 1

            try:
                proc = task.bsd_info.dereference().cast("proc")
            except exceptions.InvalidAddressException:
                continue

            if kernel_layer.is_valid(
                proc.vol.offset, proc.vol.size
            ) and not filter_func(proc):
                yield proc

    @classmethod
    def list_tasks_sessions(
        cls,
        context: interfaces.context.ContextInterface,
        kernel_module_name: str,
        filter_func: Callable[[int], bool] = lambda _: False,
    ) -> Iterable[interfaces.objects.ObjectInterface]:
        """Lists all the tasks in the primary layer using sessions

        Args:
            context: The context to retrieve required elements (layers, symbol tables) from
            kernel_module_name: The name of the kernel module on which to operate
            filter_func: A function which takes a task object and returns True if the task should be ignored/filtered

        Returns:
            The list of task objects from the `layer_name` layer's `tasks` list after filtering
        """
        kernel = context.modules[kernel_module_name]

        table_size = kernel.object_from_symbol(symbol_name="sesshash")

        sesshashtbl = kernel.object_from_symbol(symbol_name="sesshashtbl")

        proc_array = kernel.object(
            object_type="array",
            offset=sesshashtbl,
            count=table_size + 1,
            subtype=kernel.get_type("sesshashhead"),
        )

        for proc_list in proc_array:
            for proc in mac.MacUtilities.walk_list_head(proc_list, "s_hash"):
                if proc.s_leader.is_readable() and not filter_func(proc.s_leader):
                    yield proc.s_leader

    @classmethod
    def list_tasks_process_group(
        cls,
        context: interfaces.context.ContextInterface,
        kernel_module_name: str,
        filter_func: Callable[[int], bool] = lambda _: False,
    ) -> Iterable[interfaces.objects.ObjectInterface]:
        """Lists all the tasks in the primary layer using process groups

        Args:
            context: The context to retrieve required elements (layers, symbol tables) from
            kernel_module_name: The name of the kernel module on which to operate
            filter_func: A function which takes a task object and returns True if the task should be ignored/filtered

        Returns:
            The list of task objects from the `layer_name` layer's `tasks` list after filtering
        """
        kernel = context.modules[kernel_module_name]

        table_size = kernel.object_from_symbol(symbol_name="pgrphash")

        pgrphashtbl = kernel.object_from_symbol(symbol_name="pgrphashtbl")

        proc_array = kernel.object(
            object_type="array",
            offset=pgrphashtbl,
            count=table_size + 1,
            subtype=kernel.get_type("pgrphashhead"),
        )

        for proc_list in proc_array:
            for pgrp in mac.MacUtilities.walk_list_head(proc_list, "pg_hash"):
                for proc in mac.MacUtilities.walk_list_head(
                    pgrp.pg_members, "p_pglist"
                ):
                    if not filter_func(proc):
                        yield proc

    @classmethod
    def list_tasks_pid_hash_table(
        cls,
        context: interfaces.context.ContextInterface,
        kernel_module_name: str,
        filter_func: Callable[[int], bool] = lambda _: False,
    ) -> Iterable[interfaces.objects.ObjectInterface]:
        """Lists all the tasks in the primary layer using the pid hash table

        Args:
            context: The context to retrieve required elements (layers, symbol tables) from
            kernel_module_name: The name of the kernel module on which to operate
            filter_func: A function which takes a task object and returns True if the task should be ignored/filtered

        Returns:
            The list of task objects from the `layer_name` layer's `tasks` list after filtering
        """

        kernel = context.modules[kernel_module_name]

        table_size = kernel.object_from_symbol(symbol_name="pidhash")

        pidhashtbl = kernel.object_from_symbol(symbol_name="pidhashtbl")

        proc_array = kernel.object(
            object_type="array",
            offset=pidhashtbl,
            count=table_size + 1,
            subtype=kernel.get_type("pidhashhead"),
        )

        for proc_list in proc_array:
            for proc in mac.MacUtilities.walk_list_head(proc_list, "p_hash"):
                if not filter_func(proc):
                    yield proc

    def run(self):
        return renderers.TreeGrid(
            [
                ("OFFSET", format_hints.Hex),
                ("NAME", str),
                ("PID", int),
                ("UID", int),
                ("GID", int),
                ("Start Time", datetime.datetime),
                ("PPID", int),
            ],
            self._generator(),
        )
