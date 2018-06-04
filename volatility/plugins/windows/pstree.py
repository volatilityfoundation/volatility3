from volatility.framework.renderers import format_hints
from volatility.plugins.windows import pslist


class PsTree(pslist.PsList):
    """Plugin for listing processes in a tree based on their parent process ID """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._processes = {}
        self._levels = {}
        self._children = {}

    def find_level(self, pid):
        """Finds how deep the pid is in the processes list"""
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
        """Generates the """
        for proc in self.list_processes():

            if not self.config.get('physical', self.PHYSICAL_DEFAULT):
                offset = proc.vol.offset
            else:
                layer_name = self.config['primary']
                memory = self.context.memory[layer_name]
                (_, offset, _, _) = list(memory.mapping(offset = proc.vol.offset, length = 0))[0]

            self._processes[proc.UniqueProcessId] = proc

        # Build the child/level maps
        for pid in self._processes:
            self.find_level(pid)

        def yield_processes(pid):
            proc = self._processes[pid]
            row = (proc.UniqueProcessId,
                   proc.InheritedFromUniqueProcessId,
                   proc.ImageFileName.cast("string",
                                           max_length = proc.ImageFileName.vol.count,
                                           errors = 'replace'),
                   format_hints.Hex(offset),
                   proc.ActiveThreads,
                   proc.get_handle_count(),
                   proc.get_session_id(),
                   proc.get_is_wow64(),
                   proc.get_create_time(),
                   proc.get_exit_time())

            yield (self._levels[pid] - 1, row)
            for child_pid in self._children.get(pid, []):
                yield from yield_processes(child_pid)

        for pid in self._levels:
            if self._levels[pid] == 1:
                yield from yield_processes(pid)
