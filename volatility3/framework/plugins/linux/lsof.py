# This file is Copyright 2024 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
"""A module containing a collection of plugins that produce data typically
found in Linux's /proc file system."""
import logging, datetime
from typing import List, Callable

from volatility3.framework import renderers, interfaces, constants, exceptions
from volatility3.framework.configuration import requirements
from volatility3.framework.interfaces import plugins
from volatility3.framework.objects import utility
from volatility3.framework.symbols import linux
from volatility3.plugins.linux import pslist
from volatility3.plugins import timeliner

vollog = logging.getLogger(__name__)


class Lsof(plugins.PluginInterface, timeliner.TimeLinerInterface):
    """Lists all memory maps for all processes."""

    _required_framework_version = (2, 0, 0)
    _version = (2, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Linux kernel",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.PluginRequirement(
                name="pslist", plugin=pslist.PsList, version=(2, 0, 0)
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
    def get_inode_metadata(cls, filp: interfaces.objects.ObjectInterface):
        try:
            dentry = filp.get_dentry()
            if dentry:
                inode_object = dentry.d_inode
                if inode_object and inode_object.is_valid():
                    itype = (
                        inode_object.get_inode_type() or renderers.NotAvailableValue()
                    )
                    return (
                        inode_object.i_ino,
                        itype,
                        inode_object.i_size,
                        inode_object.get_file_mode(),
                        inode_object.get_change_time(),
                        inode_object.get_modification_time(),
                        inode_object.get_access_time(),
                    )
        except (exceptions.InvalidAddressException, AttributeError) as e:
            vollog.warning(f"Can't get inode metadata: {e}")
        return tuple(renderers.NotAvailableValue() for _ in range(7))

    @classmethod
    def list_fds(
        cls,
        context: interfaces.context.ContextInterface,
        symbol_table: str,
        filter_func: Callable[[int], bool] = lambda _: False,
    ):
        linuxutils_symbol_table = None
        for task in pslist.PsList.list_tasks(context, symbol_table, filter_func):
            if linuxutils_symbol_table is None:
                if constants.BANG not in task.vol.type_name:
                    raise ValueError("Task is not part of a symbol table")
                linuxutils_symbol_table = task.vol.type_name.split(constants.BANG)[0]

            task_comm = utility.array_to_string(task.comm)
            pid = int(task.pid)

            fd_generator = linux.LinuxUtilities.files_descriptors_for_process(
                context, linuxutils_symbol_table, task
            )

            for fd_fields in fd_generator:
                yield pid, task_comm, task, fd_fields

    @classmethod
    def list_fds_and_inodes(
        cls,
        context: interfaces.context.ContextInterface,
        symbol_table: str,
        filter_func: Callable[[int], bool] = lambda _: False,
    ):
        for pid, task_comm, task, (fd_num, filp, full_path) in cls.list_fds(
            context, symbol_table, filter_func
        ):
            inode_metadata = cls.get_inode_metadata(filp)
            yield pid, task_comm, task, fd_num, filp, full_path, inode_metadata

    def _generator(self, pids, symbol_table):
        filter_func = pslist.PsList.create_pid_filter(pids)
        fds_generator = self.list_fds_and_inodes(
            self.context, symbol_table, filter_func=filter_func
        )

        for (
            pid,
            task_comm,
            task,
            fd_num,
            filp,
            full_path,
            inode_metadata,
        ) in fds_generator:
            inode_num, itype, file_size, imode, ctime, mtime, atime = inode_metadata
            fields = (
                pid,
                task_comm,
                fd_num,
                full_path,
                inode_num,
                itype,
                imode,
                ctime,
                mtime,
                atime,
                file_size,
            )
            yield (0, fields)

    def run(self):
        pids = self.config.get("pid", None)
        symbol_table = self.config["kernel"]

        tree_grid_args = [
            ("PID", int),
            ("Process", str),
            ("FD", int),
            ("Path", str),
            ("Inode", int),
            ("Type", str),
            ("Mode", str),
            ("Changed", datetime.datetime),
            ("Modified", datetime.datetime),
            ("Accessed", datetime.datetime),
            ("Size", int),
        ]
        return renderers.TreeGrid(tree_grid_args, self._generator(pids, symbol_table))

    def generate_timeline(self):
        pids = self.config.get("pid", None)
        symbol_table = self.config["kernel"]
        for row in self._generator(pids, symbol_table):
            _depth, row_data = row
            description = f'Process {row_data[1]} ({row_data[0]}) Open "{row_data[3]}"'
            yield description, timeliner.TimeLinerType.CHANGED, row_data[7]
            yield description, timeliner.TimeLinerType.MODIFIED, row_data[8]
            yield description, timeliner.TimeLinerType.ACCESSED, row_data[9]
