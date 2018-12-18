"""A module containing a collection of plugins that produce data
typically found in Linux's /proc file system.
"""

from volatility.framework import exceptions, renderers
from volatility.framework.interfaces import plugins
from volatility.framework.configuration import requirements
from volatility.framework.objects import utility
from volatility.plugins.mac import pslist


class Psaux(plugins.PluginInterface):
    """Recovers program command line arguments"""

    @classmethod
    def get_requirements(cls):
        return [
            requirements.TranslationLayerRequirement(
                name = 'primary', description = 'Kernel Address Space', architectures = ["Intel32", "Intel64"]),
            requirements.SymbolRequirement(name = "darwin", description = "Mac Kernel")
        ]

    def _generator(self, tasks):
        for task in tasks:
            task_name = utility.array_to_string(task.p_comm)

            proc_layer_name = task.add_process_layer()
            if proc_layer_name is None:
                print("no proc layer")
                continue

            proc_layer = self.context.memory[proc_layer_name]

            argsstart = task.user_stack - task.p_argslen

            if not proc_layer.is_valid(argsstart) or task.p_argslen == 0 or task.p_argc == 0:
                continue

            # Add one because the first two are usually duplicates
            argc = task.p_argc + 1

            # smear protection
            if argc > 1024:
                continue

            args = []

            while argc > 0:
                try:
                    arg = proc_layer.read(argsstart, 256)
                except exceptions.PagedInvalidAddressException:
                    break

                idx = arg.find(b'\x00')
                if idx != -1:
                    arg = arg[:idx]

                argsstart += len(str(arg)) + 1

                # deal with the stupid alignment (leading nulls) and arg duplication
                if len(args) == 0:
                    while argsstart < task.user_stack:
                        try:
                            check = proc_layer.read(argsstart, 1)
                        except exceptions.PagedInvalidAddressException:
                            break

                        if check != b"\x00":
                            break

                        argsstart = argsstart + 1

                    args.append(arg)

                # also check for initial duplicates since OS X is painful
                elif arg != args[0]:
                    args.append(arg)

                argc = argc - 1

            args_str = " ".join([s.decode("utf-8") for s in args])

            yield (0, (task.p_pid, task_name, task.p_argc, args_str))

    def run(self):
        filt = pslist.PsList.create_filter([self.config.get('pid', None)])

        plugin = pslist.PsList.list_tasks

        return renderers.TreeGrid(
            [("PID", int), ("Process", str), ("Argc", int), ("Arguments", str)],
            self._generator(plugin(self.context, self.config['primary'], self.config['darwin'], filter = filt)))
