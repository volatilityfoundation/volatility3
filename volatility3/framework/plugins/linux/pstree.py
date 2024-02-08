# This file is Copyright 2021 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

from volatility3.framework import interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.renderers import format_hints
from volatility3.plugins.linux import pslist


class PsTree(interfaces.plugins.PluginInterface):
    """Plugin for listing processes in a tree based on their parent process
    ID."""

    _required_framework_version = (2, 0, 0)

    @classmethod
    def get_requirements(cls):
        # Since we're calling the plugin, make sure we have the plugin's requirements
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Linux kernel",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.PluginRequirement(
                name="pslist", plugin=pslist.PsList, version=(2, 2, 0)
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
        seen = set([pid])
        level = 0
        proc = self._tasks.get(pid)
        while proc and proc.parent and proc.parent.pid not in seen:
            if proc.is_thread_group_leader:
                parent_pid = proc.parent.pid
            else:
                parent_pid = proc.tgid

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

            row = pslist.PsList.get_task_fields(task, decorate_comm)
            # update the first element, the offset, in the row tuple to use format_hints.Hex
            # as a simple int is returned from get_task_fields.
            row = (format_hints.Hex(row[0]),) + row[1:]

            tid = task.pid
            yield (self._levels[tid] - 1, row)

            for child_pid in sorted(self._children.get(tid, [])):
                yield from yield_processes(child_pid)

        for pid, level in self._levels.items():
            if level == 1:
                yield from yield_processes(pid)

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
