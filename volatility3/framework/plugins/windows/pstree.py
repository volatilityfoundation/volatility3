# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
import datetime
import logging
from typing import Callable, Dict, Set, Tuple

from volatility3.framework import objects, interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.renderers import format_hints
from volatility3.plugins.windows import pslist

vollog = logging.getLogger(__name__)


class PsTree(interfaces.plugins.PluginInterface):
    """Plugin for listing processes in a tree based on their parent process
    ID."""

    _required_framework_version = (2, 0, 0)

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._processes: Dict[int, Tuple[interfaces.objects.ObjectInterface, int]] = {}
        self._levels: Dict[int, int] = {}
        self._children: Dict[int, Set[int]] = {}
        self._ancestors: Set[int] = set([])

    @classmethod
    def get_requirements(cls):
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Windows kernel",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.BooleanRequirement(
                name="physical",
                description="Display physical offsets instead of virtual",
                default=pslist.PsList.PHYSICAL_DEFAULT,
                optional=True,
            ),
            requirements.VersionRequirement(
                name="pslist", component=pslist.PsList, version=(2, 0, 0)
            ),
            requirements.ListRequirement(
                name="pid",
                element_type=int,
                description="Process ID to include (with ancestors and descendants, all other processes are excluded)",
                optional=True,
            ),
        ]

    def find_level(
        self,
        pid: objects.Pointer,
        filter_func: Callable[
            [interfaces.objects.ObjectInterface], bool
        ] = lambda _: False,
    ) -> None:
        """Finds how deep the pid is in the processes list."""
        seen = {pid}
        level = 0
        proc, _ = self._processes.get(pid, None)
        filtered = not filter_func(proc)
        while proc is not None and proc.InheritedFromUniqueProcessId not in seen:
            if filtered:
                self._ancestors.add(proc.UniqueProcessId)
            child_list = self._children.get(proc.InheritedFromUniqueProcessId, set([]))
            child_list.add(proc.UniqueProcessId)
            self._children[proc.InheritedFromUniqueProcessId] = child_list
            seen.add(proc.InheritedFromUniqueProcessId)
            proc, _ = self._processes.get(
                proc.InheritedFromUniqueProcessId, (None, None)
            )
            level += 1
        self._levels[pid] = level

    def _generator(
        self,
        filter_func: Callable[
            [interfaces.objects.ObjectInterface], bool
        ] = lambda _: False,
    ):
        """Generates the Tree of processes."""
        kernel = self.context.modules[self.config["kernel"]]

        for proc in pslist.PsList.list_processes(
            self.context, kernel.layer_name, kernel.symbol_table_name
        ):
            if not self.config.get("physical", pslist.PsList.PHYSICAL_DEFAULT):
                offset = proc.vol.offset
            else:
                layer_name = kernel.layer_name
                memory = self.context.layers[layer_name]
                (_, _, offset, _, _) = list(
                    memory.mapping(offset=proc.vol.offset, length=0)
                )[0]

            self._processes[proc.UniqueProcessId] = proc, offset

        # Build the child/level maps
        for pid in self._processes:
            self.find_level(pid, filter_func)

        process_pids = set([])

        def yield_processes(pid, descendant: bool = False):
            if pid in process_pids:
                vollog.debug(f"Pid cycle: already processed pid {pid}")
                return

            process_pids.add(pid)

            if pid not in self._ancestors and not descendant:
                vollog.debug(f"Pid cycle: pid {pid} not in filtered tree")
                return

            proc, offset = self._processes[pid]
            row = (
                proc.UniqueProcessId,
                proc.InheritedFromUniqueProcessId,
                proc.ImageFileName.cast(
                    "string", max_length=proc.ImageFileName.vol.count, errors="replace"
                ),
                format_hints.Hex(offset),
                proc.ActiveThreads,
                proc.get_handle_count(),
                proc.get_session_id(),
                proc.get_is_wow64(),
                proc.get_create_time(),
                proc.get_exit_time(),
            )

            yield (self._levels[pid] - 1, row)
            for child_pid in self._children.get(pid, []):
                yield from yield_processes(
                    child_pid, descendant or not filter_func(proc)
                )

        for pid in self._levels:
            if self._levels[pid] == 1:
                yield from yield_processes(pid)

    def run(self):
        offsettype = (
            "(V)"
            if not self.config.get("physical", pslist.PsList.PHYSICAL_DEFAULT)
            else "(P)"
        )

        return renderers.TreeGrid(
            [
                ("PID", int),
                ("PPID", int),
                ("ImageFileName", str),
                (f"Offset{offsettype}", format_hints.Hex),
                ("Threads", int),
                ("Handles", int),
                ("SessionId", int),
                ("Wow64", bool),
                ("CreateTime", datetime.datetime),
                ("ExitTime", datetime.datetime),
            ],
            self._generator(
                filter_func=pslist.PsList.create_pid_filter(
                    self.config.get("pid", None)
                ),
            ),
        )
