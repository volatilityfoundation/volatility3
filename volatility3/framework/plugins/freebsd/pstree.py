# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

from typing import List

from volatility3.framework import interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.interfaces import plugins
from volatility3.framework.objects import utility
from volatility3.plugins.freebsd import pslist


class PsTree(plugins.PluginInterface):
    """Plugin for listing processes in a tree based on their parent process
    ID."""

    _required_framework_version = (2, 0, 0)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._processes = {}
        self._levels = {}
        self._children = {}

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(
                name = "kernel",
                description = "Kernel module for the OS",
                architectures = ["Intel32", "Intel64"],
            ),
            requirements.PluginRequirement(name = "pslist", plugin = pslist.PsList, version = (1, 0, 0)),
        ]

    def _find_level(self, pid):
        """Finds how deep the pid is in the processes list."""
        seen = set([])
        seen.add(pid)
        level = 0
        proc = self._processes.get(pid, None)
        while proc is not None and proc.p_pptr != 0 and proc.p_pptr.p_pid not in seen:
            ppid = int(proc.p_pptr.p_pid)
            child_list = self._children.get(ppid, set([]))
            child_list.add(proc.p_pid)
            self._children[ppid] = child_list
            proc = self._processes.get(ppid, None)
            level += 1
        self._levels[pid] = level

    def _generator(self):
        """Generates the tree list of processes"""
        for proc in pslist.PsList.list_tasks(self.context, self.config["kernel"]):
            self._processes[proc.p_pid] = proc

        # Build the child/level maps
        for pid in self._processes:
            self._find_level(pid)

        def yield_processes(pid):
            proc = self._processes[pid]
            row = (proc.p_pid, proc.p_pptr.p_pid, utility.array_to_string(proc.p_comm))

            yield (self._levels[pid] - 1, row)
            for child_pid in self._children.get(pid, []):
                yield from yield_processes(child_pid)

        for pid in self._levels:
            if self._levels[pid] == 1:
                yield from yield_processes(pid)

    def run(self):
        return renderers.TreeGrid([("PID", int), ("PPID", int), ("COMM", str)], self._generator())
