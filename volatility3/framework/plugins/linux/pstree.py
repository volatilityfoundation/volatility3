# This file is Copyright 2021 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

from volatility3.plugins.linux import pslist


class PsTree(pslist.PsList):
    """Plugin for listing processes in a tree based on their parent process
    ID."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._tasks = {}
        self._levels = {}
        self._children = {}

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
        self, pid_filter, include_threads: bool = False, decorate_com: bool = False
    ):
        """Generates the tasks hierarchy tree.

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
        vmlinux = self.context.modules[self.config["kernel"]]
        for proc in self.list_tasks(
            self.context,
            vmlinux.name,
            filter_func=pid_filter,
            include_threads=include_threads,
        ):
            self._tasks[proc.pid] = proc

        # Build the child/level maps
        for pid in self._tasks:
            self.find_level(pid)

        def yield_processes(pid):
            task = self._tasks[pid]

            row = self._get_task_fields(task, decorate_com)

            tid = task.pid
            yield (self._levels[tid] - 1, row)

            for child_pid in sorted(self._children.get(tid, [])):
                yield from yield_processes(child_pid)

        for pid, level in self._levels.items():
            if level == 1:
                yield from yield_processes(pid)
