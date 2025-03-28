# This file is Copyright 2024 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
import logging
import datetime
import dataclasses
from typing import List, Callable, Tuple, Iterable

from volatility3.framework import renderers, interfaces, constants
from volatility3.framework.configuration import requirements
from volatility3.framework.interfaces import plugins
from volatility3.framework.objects import utility
from volatility3.framework.symbols import linux
from volatility3.plugins.linux import pslist
from volatility3.plugins import timeliner

vollog = logging.getLogger(__name__)


@dataclasses.dataclass
class FDUser:
    """FD user representation, featuring augmented information and formatted fields.
    This is the data the plugin will eventually display.
    """

    task_tgid: int
    task_tid: int
    task_comm: str
    fd_num: int
    full_path: str
    device: str = dataclasses.field(default=renderers.NotAvailableValue())
    inode_num: int = dataclasses.field(default=renderers.NotAvailableValue())
    inode_type: str = dataclasses.field(default=renderers.NotAvailableValue())
    file_mode: str = dataclasses.field(default=renderers.NotAvailableValue())
    change_time: datetime.datetime = dataclasses.field(
        default=renderers.NotAvailableValue()
    )
    modification_time: datetime.datetime = dataclasses.field(
        default=renderers.NotAvailableValue()
    )
    access_time: datetime.datetime = dataclasses.field(
        default=renderers.NotAvailableValue()
    )
    inode_size: int = dataclasses.field(default=renderers.NotAvailableValue())


@dataclasses.dataclass
class FDInternal:
    """FD internal representation containing only the core objects

    Fields:
        task: 'task_struct' object
        fd_fields: FD fields as obtained from LinuxUtilities.files_descriptors_for_process()
    """

    task: interfaces.objects.ObjectInterface
    fd_fields: Tuple[int, interfaces.objects.ObjectInterface, str]

    def to_user(self) -> FDUser:
        """Augment the FD information to be presented to the user

        Returns:
            An InodeUser dataclass
        """
        # Ensure all types are atomic immutable. Otherwise, astuple() will take a long
        # time doing a deepcopy of the Volatility objects.
        task_tgid = int(self.task.tgid)
        task_tid = int(self.task.pid)
        task_comm = utility.array_to_string(self.task.comm)
        fd_num, filp, full_path = self.fd_fields
        fd_num = int(fd_num)
        full_path = str(full_path)
        inode = filp.get_inode()
        if inode:
            superblock_ptr = inode.i_sb
            if superblock_ptr and superblock_ptr.is_readable():
                device = f"{superblock_ptr.major}:{superblock_ptr.minor}"
            else:
                device = renderers.NotAvailableValue()

            fd_user = FDUser(
                task_tgid=task_tgid,
                task_tid=task_tid,
                task_comm=task_comm,
                fd_num=fd_num,
                full_path=full_path,
                device=device,
                inode_num=int(inode.i_ino),
                inode_type=inode.get_inode_type() or renderers.UnparsableValue(),
                file_mode=inode.get_file_mode(),
                change_time=inode.get_change_time(),
                modification_time=inode.get_modification_time(),
                access_time=inode.get_access_time(),
                inode_size=int(inode.i_size),
            )
        else:
            # We use the dataclasses' default values
            fd_user = FDUser(
                task_tgid=task_tgid,
                task_tid=task_tid,
                task_comm=task_comm,
                fd_num=fd_num,
                full_path=full_path,
            )

        return fd_user


class Lsof(plugins.PluginInterface, timeliner.TimeLinerInterface):
    """Lists open files for each processes."""

    _required_framework_version = (2, 0, 0)
    _version = (2, 0, 2)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Linux kernel",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.VersionRequirement(
                name="pslist", component=pslist.PsList, version=(4, 0, 0)
            ),
            requirements.VersionRequirement(
                name="timeliner",
                component=timeliner.TimeLinerInterface,
                version=(1, 0, 0),
            ),
            requirements.VersionRequirement(
                name="linuxutils", component=linux.LinuxUtilities, version=(2, 0, 0)
            ),
            requirements.ListRequirement(
                name="pid",
                description="Filter on specific process IDs",
                element_type=int,
                optional=True,
            ),
        ]

    @classmethod
    def list_fds(
        cls,
        context: interfaces.context.ContextInterface,
        vmlinux_module_name: str,
        filter_func: Callable[[int], bool] = lambda _: False,
    ) -> Iterable[FDInternal]:
        """Enumerates open file descriptors in tasks

        Args:
            context: The context to retrieve required elements (layers, symbol tables) from
            vmlinux_module_name: The name of the kernel module on which to operate
            filter_func: A function which takes a process object and returns True if the process
                should be ignored/filtered

        Yields:
            A FDInternal object
        """
        linuxutils_symbol_table = None
        for task in pslist.PsList.list_tasks(
            context, vmlinux_module_name, filter_func, include_threads=True
        ):
            if linuxutils_symbol_table is None:
                if constants.BANG not in task.vol.type_name:
                    raise ValueError("Task is not part of a symbol table")
                linuxutils_symbol_table = task.vol.type_name.split(constants.BANG)[0]

            fd_generator = linux.LinuxUtilities.files_descriptors_for_process(
                context, linuxutils_symbol_table, task
            )

            for fd_fields in fd_generator:
                yield FDInternal(task=task, fd_fields=fd_fields)

    def _generator(self, pids, vmlinux_module_name):
        filter_func = pslist.PsList.create_pid_filter(pids)
        for fd_internal in self.list_fds(
            self.context, vmlinux_module_name, filter_func=filter_func
        ):
            fd_user = fd_internal.to_user()
            yield (0, dataclasses.astuple(fd_user))

    def run(self):
        pids = self.config.get("pid", None)
        vmlinux_module_name = self.config["kernel"]

        tree_grid_args = [
            ("PID", int),
            ("TID", int),
            ("Process", str),
            ("FD", int),
            ("Path", str),
            ("Device", str),
            ("Inode", int),
            ("Type", str),
            ("Mode", str),
            ("Changed", datetime.datetime),
            ("Modified", datetime.datetime),
            ("Accessed", datetime.datetime),
            ("Size", int),
        ]
        return renderers.TreeGrid(
            tree_grid_args, self._generator(pids, vmlinux_module_name)
        )

    def generate_timeline(self):
        pids = self.config.get("pid", None)
        vmlinux_module_name = self.config["kernel"]

        filter_func = pslist.PsList.create_pid_filter(pids)
        for fd_internal in self.list_fds(
            self.context, vmlinux_module_name, filter_func=filter_func
        ):
            fd_user = fd_internal.to_user()

            description = (
                f"Process {fd_user.task_comm} ({fd_user.task_tgid}/{fd_user.task_tid}) "
                f"Open '{fd_user.full_path}'"
            )

            yield description, timeliner.TimeLinerType.CHANGED, fd_user.change_time
            yield description, timeliner.TimeLinerType.MODIFIED, fd_user.modification_time
            yield description, timeliner.TimeLinerType.ACCESSED, fd_user.access_time
