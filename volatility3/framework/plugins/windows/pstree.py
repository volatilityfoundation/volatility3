# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
import datetime
from typing import Dict, Set

from volatility3.framework import objects, interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.renderers import format_hints
from volatility3.plugins.windows import pslist


class PsTree(interfaces.plugins.PluginInterface):
    """Plugin for listing processes in a tree based on their parent process
    ID."""

    _required_framework_version = (1, 0, 0)

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._processes = {}  # type: Dict[int, interfaces.objects.ObjectInterface]
        self._levels = {}  # type: Dict[int, int]
        self._children = {}  # type: Dict[int, Set[int]]

    @classmethod
    def get_requirements(cls):
        return [
            requirements.TranslationLayerRequirement(name = 'primary',
                                                     description = 'Memory layer for the kernel',
                                                     architectures = ["Intel32", "Intel64"]),
            requirements.SymbolTableRequirement(name = "nt_symbols", description = "Windows kernel symbols"),
            requirements.BooleanRequirement(name = 'physical',
                                            description = 'Display physical offsets instead of virtual',
                                            default = pslist.PsList.PHYSICAL_DEFAULT,
                                            optional = True),
            requirements.VersionRequirement(name = 'pslist', component = pslist.PsList, version = (2, 0, 0)),
            requirements.ListRequirement(name = 'pid',
                                         element_type = int,
                                         description = "Process ID to include (all other processes are excluded)",
                                         optional = True)
        ]

    def find_level(self, pid: objects.Pointer) -> None:
        """Finds how deep the pid is in the processes list."""
        seen = set([])
        seen.add(pid)
        level = 0
        proc = self._processes.get(pid, None)
        while proc is not None and proc.InheritedFromUniqueProcessId not in seen:
            child_list = self._children.get(proc.InheritedFromUniqueProcessId, set([]))
            child_list.add(proc.UniqueProcessId)
            self._children[proc.InheritedFromUniqueProcessId] = child_list
            proc = self._processes.get(proc.InheritedFromUniqueProcessId, None)
            level += 1
        self._levels[pid] = level

    def _generator(self):
        """Generates the Tree of processes."""
        for proc in pslist.PsList.list_processes(self.context, self.config['primary'], self.config['nt_symbols']):

            if not self.config.get('physical', pslist.PsList.PHYSICAL_DEFAULT):
                offset = proc.vol.offset
            else:
                layer_name = self.config['primary']
                memory = self.context.layers[layer_name]
                (_, _, offset, _, _) = list(memory.mapping(offset = proc.vol.offset, length = 0))[0]

            self._processes[proc.UniqueProcessId] = proc

        # Build the child/level maps
        for pid in self._processes:
            self.find_level(pid)

        def yield_processes(pid):
            proc = self._processes[pid]
            row = (proc.UniqueProcessId, proc.InheritedFromUniqueProcessId,
                   proc.ImageFileName.cast("string", max_length = proc.ImageFileName.vol.count, errors = 'replace'),
                   format_hints.Hex(offset), proc.ActiveThreads, proc.get_handle_count(), proc.get_session_id(),
                   proc.get_is_wow64(), proc.get_create_time(), proc.get_exit_time())

            yield (self._levels[pid] - 1, row)
            for child_pid in self._children.get(pid, []):
                yield from yield_processes(child_pid)

        for pid in self._levels:
            if self._levels[pid] == 1:
                yield from yield_processes(pid)

    def run(self):
        offsettype = "(V)" if not self.config.get('physical', pslist.PsList.PHYSICAL_DEFAULT) else "(P)"

        return renderers.TreeGrid([("PID", int), ("PPID", int), ("ImageFileName", str),
                                   ("Offset{0}".format(offsettype), format_hints.Hex), ("Threads", int),
                                   ("Handles", int), ("SessionId", int), ("Wow64", bool),
                                   ("CreateTime", datetime.datetime), ("ExitTime", datetime.datetime)],
                                  self._generator())
