# This file is Copyright 2021 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

import logging

from volatility3.framework import interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.renderers import format_hints
from volatility3.plugins.linux import pslist

vollog = logging.getLogger(__name__)


class PsTree(interfaces.plugins.PluginInterface):
    """Plugin for listing processes in a tree based on their parent process ID."""

    _required_framework_version = (2, 13, 0)
    _version = (1, 1, 1)

    @classmethod
    def get_requirements(cls):
        # Since we're calling the plugin, make sure we have the plugin's requirements
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Linux kernel",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.VersionRequirement(
                name="pslist", component=pslist.PsList, version=(4, 0, 0)
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

    def find_level(self, pid: int) -> None:
        """Finds how deep the PID is in the tasks hierarchy.

        Args:
            pid: PID to find the level in the hierarchy
        """
        seen_ppids = set()
        seen_offsets = set()

        level = 0
        proc = self._tasks.get(pid)

        while proc:
            # we don't want swapper in the tree
            if proc.pid == 0:
                break

            if proc.is_thread_group_leader:
                parent_pid = proc.get_parent_pid()
            else:
                parent_pid = proc.tgid

            if parent_pid in seen_ppids or proc.vol.offset in seen_offsets:
                break

            # only pid 1 (init/systemd) or 2 (kthreadd) should have swapper as a parent
            # any other process with a ppid of 0 is smeared or terminated
            if parent_pid == 0 and proc.pid > 2:
                vollog.debug(
                    "Smeared process with parent PID of 0 and PID greater than 2 ({proc.pid}) is being skipped."
                )
                break

            seen_ppids.add(parent_pid)
            seen_offsets.add(proc.vol.offset)

            child_list = self._children.setdefault(parent_pid, set())
            child_list.add(proc.pid)

            proc = self._tasks.get(parent_pid)

            level += 1

        self._levels[pid] = level

    def _generator(
        self,
        tasks: list,
        decorate_comm: bool = False,
    ):
        """Generates the tasks hierarchy tree.

        Args:
            tasks: A list of task objects to be displayed
            decorate_comm: If True, it decorates the comm string of
                            - User threads: in curly brackets,
                            - Kernel threads: in square brackets
                           Defaults to False.
        Yields:
            Each rows
        """

        self._tasks = {}
        self._levels = {}
        self._children = {}

        for proc in tasks:
            self._tasks[proc.pid] = proc

        # Build the child/level maps
        for pid in self._tasks:
            self.find_level(pid)

        def yield_processes(pid):
            task = self._tasks[pid]

            task_fields = pslist.PsList.get_task_fields(task, decorate_comm)
            fields = (
                format_hints.Hex(task_fields.offset),
                task_fields.user_pid,
                task_fields.user_tid,
                task_fields.user_ppid,
                task_fields.name,
            )
            yield (self._levels[task_fields.user_tid] - 1, fields)

            seen_children = set()

            for child_pid in sorted(self._children.get(task_fields.user_tid, [])):
                if child_pid in seen_children:
                    break
                seen_children.add(child_pid)

                yield from yield_processes(child_pid)

        seen_processes = set()

        for pid, level in self._levels.items():
            if level == 1:
                for fields in yield_processes(pid):
                    pid = fields[1]
                    if pid in seen_processes:
                        break
                    seen_processes.add(pid)

                    yield fields

    def run(self):
        filter_func = pslist.PsList.create_pid_filter(self.config.get("pid", None))
        include_threads = self.config.get("threads")
        decorate_comm = self.config.get("decorate_comm")

        return renderers.TreeGrid(
            [
                ("OFFSET (V)", format_hints.Hex),
                ("PID", int),
                ("TID", int),
                ("PPID", int),
                ("COMM", str),
            ],
            self._generator(
                pslist.PsList.list_tasks(
                    self.context,
                    self.config["kernel"],
                    filter_func=filter_func,
                    include_threads=include_threads,
                ),
                decorate_comm=decorate_comm,
            ),
        )
