# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
"""A module containing a collection of plugins that produce data typically
found in Linux's /proc file system."""
import logging
from typing import List, Callable

from volatility3.framework import renderers, interfaces, constants
from volatility3.framework.configuration import requirements
from volatility3.framework.interfaces import plugins
from volatility3.framework.objects import utility
from volatility3.framework.symbols import linux
from volatility3.plugins.linux import pslist, psscan

vollog = logging.getLogger(__name__)


class Lsof(plugins.PluginInterface):
    """Lists all memory maps for all processes."""

    _required_framework_version = (2, 0, 0)

    _version = (1, 2, 0)

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
            requirements.PluginRequirement(
                name="psscan", plugin=psscan.PsScan, version=(1, 1, 0)
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
            requirements.BooleanRequirement(
                name="scan",
                description="Scan for processes rather than using pslist",
                optional=True,
                default=False,
            ),
        ]

    @classmethod
    def list_fds(
        cls,
        context: interfaces.context.ContextInterface,
        symbol_table: str,
        filter_func: Callable[[int], bool] = lambda _: False,
        scan: bool = False,
    ):
        linuxutils_symbol_table = None  # type: ignore

        # select the function used to find task objects
        if scan:
            vmlinux = context.modules[symbol_table]
            task_finder_function = psscan.PsScan.scan_tasks(
                context,
                symbol_table,
                vmlinux.layer_name,
                filter_func=filter_func,
            )
        else:
            task_finder_function = pslist.PsList.list_tasks(
                context, symbol_table, filter_func
            )

        for task in task_finder_function:
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

    def _generator(self, pids, symbol_table, scan):
        filter_func = pslist.PsList.create_pid_filter(pids)
        fds_generator = self.list_fds(
            self.context, symbol_table, filter_func=filter_func, scan=scan
        )

        for pid, task_comm, _task, fd_fields in fds_generator:
            fd_num, _filp, full_path = fd_fields

            fields = (pid, task_comm, fd_num, full_path)
            yield (0, fields)

    def run(self):
        pids = self.config.get("pid", None)
        symbol_table = self.config["kernel"]
        scan = self.config.get("scan", None)

        tree_grid_args = [("PID", int), ("Process", str), ("FD", int), ("Path", str)]
        return renderers.TreeGrid(
            tree_grid_args, self._generator(pids, symbol_table, scan)
        )
