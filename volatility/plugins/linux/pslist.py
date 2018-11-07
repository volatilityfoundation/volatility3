import typing

import volatility.framework.interfaces.plugins as interfaces_plugins
from volatility.framework import renderers, interfaces
from volatility.framework.automagic import linux
from volatility.framework.configuration import requirements
from volatility.framework.objects import utility


class PsList(interfaces_plugins.PluginInterface):
    """Lists the processes present in a particular linux memory image"""

    @classmethod
    def get_requirements(cls):
        return [requirements.TranslationLayerRequirement(name = 'primary',
                                                         description = 'Kernel Address Space',
                                                         architectures = ["Intel32", "Intel64"]),
                requirements.SymbolRequirement(name = "vmlinux",
                                               description = "Linux Kernel")]

    @classmethod
    def create_filter(cls, pid_list: typing.List[int] = None) -> typing.Callable[[int], bool]:
        filter = lambda _: False
        # FIXME: mypy #4973 or #2608
        pid_list = pid_list or []
        filter_list = [x for x in pid_list if x is not None]
        if filter_list:
            filter = lambda x: x not in filter_list
        return filter

    def _generator(self):
        for task in self.list_tasks(self.context,
                                    self.config['primary'],
                                    self.config['vmlinux'],
                                    filter = self.create_filter([self.config.get('pid', None)])):
            pid = task.pid
            ppid = 0
            if task.parent:
                ppid = task.parent.pid
            name = utility.array_to_string(task.comm)
            yield (0, (pid, ppid, name))

    @classmethod
    def list_tasks(cls,
                   context: interfaces.context.ContextInterface,
                   layer_name: str,
                   vmlinux_symbols: str,
                   filter: typing.Callable[[int], bool] = lambda _: False) -> \
            typing.Iterable[interfaces.objects.ObjectInterface]:

        """Lists all the tasks in the primary layer"""

        _, aslr_shift = linux.LinuxUtilities.find_aslr(context, vmlinux_symbols, layer_name)
        vmlinux = context.module(vmlinux_symbols, layer_name, aslr_shift)
        init_task = vmlinux.object(symbol_name = "init_task")

        for task in init_task.tasks:
            yield task

    def run(self):
        return renderers.TreeGrid([("PID", int),
                                   ("PPID", int),
                                   ("COMM", str)],
                                  self._generator())
