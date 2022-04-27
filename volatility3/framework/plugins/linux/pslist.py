# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
import datetime

from typing import Callable, Iterable, List, Any

from volatility3.framework import renderers, interfaces
from volatility3.framework.configuration import requirements
from volatility3.framework.objects import utility
from volatility3.framework.symbols import intermed
from volatility3.framework.symbols.linux.extensions import elf
from volatility3.plugins.linux import elfs

class PsList(interfaces.plugins.PluginInterface):
    """Lists the processes present in a particular linux memory image."""

    _required_framework_version = (2, 0, 0)

    _version = (2, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(name = 'kernel', description = 'Linux kernel',
                                           architectures = ["Intel32", "Intel64"]),
            requirements.PluginRequirement(name = 'elfs', plugin = elfs.Elfs, version = (2, 0, 0)),
            requirements.ListRequirement(name = 'pid',
                                         description = 'Filter on specific process IDs',
                                         element_type = int,
                                         optional = True),
            requirements.BooleanRequirement(name = 'dump',
                                            description = "Extract listed processes",
                                            default = False,
                                            optional = True)
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
        elf_table_name = intermed.IntermediateSymbolTable.create(self.context,
                                                                 self.config_path,
                                                                 "linux",
                                                                 "elf",
                                                                 class_types = elf.class_types)


        vmlinux = self.context.modules[self.config['kernel']]
        # These timekeeper variables are introduced in kernel 3.19
        timekeeper = vmlinux.object_from_symbol(symbol_name = "tk_core").timekeeper
        boot_time_nano = timekeeper.offs_real - timekeeper.offs_boot

        for task in self.list_tasks(self.context,
                                    self.config['kernel'],
                                    filter_func = self.create_pid_filter(self.config.get('pid', None))):
            pid = task.pid
            ppid = 0
            if task.parent:
                ppid = task.parent.pid
            name = utility.array_to_string(task.comm)
            uid = task.real_cred.uid.val
            gid = task.real_cred.gid.val

            # task.(real_)start_time contains amount of nanoseconds since boottime
            create_timespec = task.real_start_time if hasattr(task, "real_start_time") else task.start_time
            create_timespec_sec = int(create_timespec / 1e9)
            create_timespec_nsec = create_timespec % 1e9
            create_time = datetime.datetime.fromtimestamp(boot_time_nano / 1e9) + datetime.timedelta(
                seconds = create_timespec_sec, microseconds = int(create_timespec_nsec / 1e3))

            file_output = "Disabled"
            if self.config['dump']:
                proc_layer_name = task.add_process_layer()
                if not proc_layer_name:
                    continue

                # Find the vma that belongs to the main ELF of the process
                vma = None
                for v in task.mm.get_mmap_iter():
                    if v.vm_start == task.mm.start_code:
                        vma = v
                        break
                if vma is not None:
                    file_handle = elfs.Elfs.elf_dump(self.context, proc_layer_name, elf_table_name, vma, task,
                                                     self.open)
                file_output = "Error outputting file"
                if file_handle:
                    file_handle.close()
                    file_output = str(file_handle.preferred_filename)

            yield (0, (pid, ppid, uid, gid, name, create_time, file_output))

    @classmethod
    def list_tasks(
            cls,
            context: interfaces.context.ContextInterface,
            vmlinux_module_name: str,
            filter_func: Callable[[int], bool] = lambda _: False) -> Iterable[interfaces.objects.ObjectInterface]:
        """Lists all the tasks in the primary layer.

        Args:
            context: The context to retrieve required elements (layers, symbol tables) from
            vmlinux_module_name: The name of the kernel module on which to operate

        Yields:
            Process objects
        """
        vmlinux = context.modules[vmlinux_module_name]

        init_task = vmlinux.object_from_symbol(symbol_name = "init_task")

        # Note that the init_task itself is not yielded, since "ps" also never shows it.
        for task in init_task.tasks:
            if not filter_func(task):
                yield task

    def run(self):
        return renderers.TreeGrid([("PID", int), ("PPID", int), ("UID", int), ("GID", int), ("COMM", str),
                                   ("CreateTime", datetime.datetime),  ("File output", str)], self._generator())
