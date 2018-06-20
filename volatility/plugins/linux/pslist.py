import volatility.framework.interfaces.plugins as interfaces_plugins
from volatility.framework import renderers
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

    def _generator(self):
        for task in self.list_tasks(self.context, self.config['primary'], self.config['vmlinux']):
            pid = task.pid
            ppid = 0
            if task.parent:
                ppid = task.parent.pid
            name = utility.array_to_string(task.comm)
            yield (0, (pid, ppid, name))

    @classmethod
    def list_tasks(cls, context, primary_layer: str, vmlinux_table: str):
        """Lists all the tasks in the primary layer"""

        layer_name = context.memory[primary_layer].config['memory_layer']

        _, aslr_shift = linux.LinuxUtilities.find_aslr(context, vmlinux_table, layer_name)
        vmlinux = context.module(vmlinux_table, primary_layer, aslr_shift)
        init_task = vmlinux.object(symbol_name = "init_task")

        for task in init_task.tasks:
            yield task

    def run(self):
        return renderers.TreeGrid([("PID", int),
                                   ("PPID", int),
                                   ("COMM", str)],
                                  self._generator())
