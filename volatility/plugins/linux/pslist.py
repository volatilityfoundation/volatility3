import volatility.framework.interfaces.plugins as plugins
from volatility.framework.configuration import requirements
from volatility.framework.renderers import TreeGrid
from volatility.framework.objects.utility import array_to_string


class PsList(plugins.PluginInterface):
    @classmethod
    def get_requirements(cls):
        return [requirements.TranslationLayerRequirement(name = 'primary',
                                                         description = 'Kernel Address Space',
                                                         architectures = ["Intel32", "Intel64"]),
                requirements.SymbolRequirement(name = "vmlinux",
                                               description = "Linux Kernel")]

    def update_configuration(self):
        """No operation since all values provided by config/requirements initially"""

    def _generator(self):
        for task in self.list_tasks():
            pid = task.pid
            ppid = 0
            if task.parent:
                ppid = task.parent.pid
            name = array_to_string(task.comm)
            yield (0, (pid, ppid, name))

    def list_tasks(self):
        """Lists all the tasks in the primary layer"""

        layer_name = self.config['primary']

        # TODO: Will need to compute a non-zero offset for ASLR kernels
        vmlinux = self.context.module("vmlinux", "primary", 0)
        init_task = vmlinux.object(symbol_name="init_task")

        for task in init_task.tasks:
            yield task

    def run(self):
        return TreeGrid([("PID", int),
                         ("PPID", int),
                         ("COMM", str)],
                        self._generator())
