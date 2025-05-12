# This file is Copyright 2021 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
import datetime
import dataclasses
import contextlib
from typing import Any, Callable, Iterable, List, Optional

from volatility3.framework import interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.objects import utility
from volatility3.framework.renderers import format_hints
from volatility3.framework.symbols import intermed
from volatility3.framework.symbols.linux.extensions import elf
from volatility3.plugins import timeliner
from volatility3.plugins.linux import elfs


@dataclasses.dataclass
class TaskFields:
    offset: int
    user_pid: int
    user_tid: int
    user_ppid: int
    name: str
    uid: Optional[int]
    gid: Optional[int]
    euid: Optional[int]
    egid: Optional[int]
    creation_time: Optional[datetime.datetime]


class PsList(interfaces.plugins.PluginInterface, timeliner.TimeLinerInterface):
    """Lists the processes present in a particular linux memory image."""

    _required_framework_version = (2, 13, 0)
    _version = (4, 1, 1)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Linux kernel",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.VersionRequirement(
                name="elfs", component=elfs.Elfs, version=(2, 0, 0)
            ),
            requirements.ListRequirement(
                name="pid",
                description="Filter on specific process IDs",
                element_type=int,
                optional=True,
            ),
            requirements.VersionRequirement(
                name="timeliner",
                component=timeliner.TimeLinerInterface,
                version=(1, 0, 0),
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
            requirements.BooleanRequirement(
                name="dump",
                description="Extract listed processes",
                optional=True,
                default=False,
            ),
        ]

    @classmethod
    def create_pid_filter(
        cls, pid_list: Optional[List[int]] = None
    ) -> Callable[[Any], bool]:
        """Constructs a filter function for process IDs.

        Args:
            pid_list: List of process IDs that are acceptable (or None if all are acceptable)

        Returns:
            Function which, when provided a process object, returns True if the process is to be filtered out of the list
        """
        pid_list = pid_list or []
        filter_list = [x for x in pid_list if x is not None]
        if filter_list:

            def filter_func(x):
                return x.pid not in filter_list

            return filter_func
        else:
            return lambda _: False

    @classmethod
    def get_task_fields(
        cls, task: interfaces.objects.ObjectInterface, decorate_comm: bool = False
    ) -> TaskFields:
        """Extract the fields needed for the final output

        Args:
            task: A task object from where to get the fields.
            decorate_comm: If True, it decorates the comm string of user threads in curly brackets,
                           and of Kernel threads in square brackets.
                           Defaults to False.
        Returns:
            A TaskFields object with the fields to show in the plugin output.
        """
        name = utility.array_to_string(task.comm)
        if decorate_comm:
            if task.is_kernel_thread:
                name = f"[{name}]"
            elif task.is_user_thread:
                name = f"{{{name}}}"

        # This function may be called with a partially initialized/uninitialized task.
        # Ensure it always returns a valid TaskFields object, ready for use in a plugin.
        valid_cred = task.cred and task.cred.is_readable()
        creation_time = None
        with contextlib.suppress(Exception):
            creation_time = task.get_create_time()

        return TaskFields(
            offset=task.vol.offset,
            user_pid=task.tgid,
            user_tid=task.pid,
            user_ppid=task.get_parent_pid(),
            name=name,
            uid=task.cred.uid if valid_cred else None,
            gid=task.cred.gid if valid_cred else None,
            euid=task.cred.euid if valid_cred else None,
            egid=task.cred.egid if valid_cred else None,
            creation_time=creation_time,
        )

    def _get_file_output(self, task: interfaces.objects.ObjectInterface) -> str:
        """Extract the elf for the process if requested
        Args:
            task: A task object to extract from.
        Returns:
            A string showing the results of the extraction, either
            the filename used or an error.
        """
        elf_table_name = intermed.IntermediateSymbolTable.create(
            self.context,
            self.config_path,
            "linux",
            "elf",
            class_types=elf.class_types,
        )
        proc_layer_name = task.add_process_layer()
        if not proc_layer_name:
            # if we can't build a proc layer we can't
            # extract the elf
            return renderers.NotApplicableValue()
        else:
            # Find the vma that belongs to the main ELF of the process
            file_output = "Error outputting file"
            for v in task.mm.get_vma_iter():
                if v.vm_start == task.mm.start_code:
                    file_handle = elfs.Elfs.elf_dump(
                        self.context,
                        proc_layer_name,
                        elf_table_name,
                        v,
                        task,
                        self.open,
                    )
                    if file_handle:
                        file_output = str(file_handle.preferred_filename)
                        file_handle.close()
                    break
            else:
                file_output = "VMA start matching task start_code not found"
        return file_output

    @staticmethod
    def _format_cred(cred):
        return renderers.NotAvailableValue() if cred is None else cred

    def _generator(
        self,
        pid_filter: Callable[[Any], bool],
        include_threads: bool = False,
        decorate_comm: bool = False,
        dump: bool = False,
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
            dump: If True, the main executable of the process is written to a file
                  Defaults to False.
        Yields:
            Each rows
        """
        for task in self.list_tasks(
            self.context, self.config["kernel"], pid_filter, include_threads
        ):
            if dump:
                file_output = self._get_file_output(task)
            else:
                file_output = "Disabled"

            task_fields = self.get_task_fields(task, decorate_comm)

            task_uid = self._format_cred(task_fields.uid)
            task_gid = self._format_cred(task_fields.gid)
            task_euid = self._format_cred(task_fields.euid)
            task_egid = self._format_cred(task_fields.egid)

            yield 0, (
                format_hints.Hex(task_fields.offset),
                task_fields.user_pid,
                task_fields.user_tid,
                task_fields.user_ppid,
                task_fields.name,
                task_uid,
                task_gid,
                task_euid,
                task_egid,
                task_fields.creation_time or renderers.NotAvailableValue(),
                file_output,
            )

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
        seen = set()
        for forward in (True, False):
            for task in init_task.tasks.to_list(
                symbol_type=init_task.vol.type_name,
                member="tasks",
                forward=forward,
            ):
                if task.vol.offset in seen:
                    continue
                seen.add(task.vol.offset)

                if not task.is_valid():
                    continue

                if filter_func(task):
                    continue

                yield task

                if include_threads:
                    yield from task.get_threads()

    def run(self):
        pids = self.config.get("pid")
        include_threads = self.config.get("threads")
        decorate_comm = self.config.get("decorate_comm")
        dump = self.config.get("dump")
        filter_func = self.create_pid_filter(pids)

        columns = [
            ("OFFSET (V)", format_hints.Hex),
            ("PID", int),
            ("TID", int),
            ("PPID", int),
            ("COMM", str),
            ("UID", int),
            ("GID", int),
            ("EUID", int),
            ("EGID", int),
            ("CREATION TIME", datetime.datetime),
            ("File output", str),
        ]
        return renderers.TreeGrid(
            columns, self._generator(filter_func, include_threads, decorate_comm, dump)
        )

    def generate_timeline(self):
        pids = self.config.get("pid")
        filter_func = self.create_pid_filter(pids)
        for task in self.list_tasks(
            self.context, self.config["kernel"], filter_func, include_threads=True
        ):
            task_fields = self.get_task_fields(task)
            description = f"Process {task_fields.user_pid}/{task_fields.user_tid} {task_fields.name} ({task_fields.offset})"

            yield (
                description,
                timeliner.TimeLinerType.CREATED,
                task_fields.creation_time,
            )
