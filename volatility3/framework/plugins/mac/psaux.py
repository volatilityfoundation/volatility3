# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
"""In-memory artifacts from OSX systems."""
from typing import Iterator, Tuple, Any, Generator, List

from volatility3.framework import exceptions, renderers, interfaces
from volatility3.framework.configuration import requirements
from volatility3.framework.interfaces import plugins
from volatility3.framework.objects import utility
from volatility3.plugins.mac import pslist


class Psaux(plugins.PluginInterface):
    """Recovers program command line arguments."""

    _required_framework_version = (2, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Kernel module for the OS",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.PluginRequirement(
                name="pslist", plugin=pslist.PsList, version=(3, 0, 0)
            ),
            requirements.ListRequirement(
                name="pid",
                description="Filter on specific process IDs",
                element_type=int,
                optional=True,
            ),
        ]

    def _generator(
        self, tasks: Iterator[Any]
    ) -> Generator[Tuple[int, Tuple[int, str, int, str]], None, None]:
        for task in tasks:
            proc_layer_name = task.add_process_layer()
            if proc_layer_name is None:
                continue

            proc_layer = self.context.layers[proc_layer_name]

            argsstart = task.user_stack - task.p_argslen

            if (
                not proc_layer.is_valid(argsstart)
                or task.p_argslen == 0
                or task.p_argc == 0
            ):
                continue

            # Add one because the first two are usually duplicates
            argc = task.p_argc + 1

            # smear protection
            if argc > 1024:
                continue

            task_name = utility.array_to_string(task.p_comm)

            args: List[bytes] = []

            while argc > 0:
                try:
                    arg = proc_layer.read(argsstart, 256)
                except exceptions.InvalidAddressException:
                    break

                idx = arg.find(b"\x00")
                if idx != -1:
                    arg = arg[:idx]

                argsstart += len(str(arg)) + 1

                # deal with the stupid alignment (leading nulls) and arg duplication
                if len(args) == 0:
                    while argsstart < task.user_stack:
                        try:
                            check = proc_layer.read(argsstart, 1)
                        except exceptions.InvalidAddressException:
                            break

                        if check != b"\x00":
                            break

                        argsstart = argsstart + 1

                    args.append(arg)

                # also check for initial duplicates since OS X is painful
                elif arg != args[0]:
                    args.append(arg)

                argc = argc - 1

            args_str = " ".join([s.decode("utf-8", errors="replace") for s in args])

            yield (0, (task.p_pid, task_name, task.p_argc, args_str))

    def run(self) -> renderers.TreeGrid:
        filter_func = pslist.PsList.create_pid_filter(self.config.get("pid", None))
        list_tasks = pslist.PsList.get_list_tasks(
            self.config.get("pslist_method", pslist.PsList.pslist_methods[0])
        )

        return renderers.TreeGrid(
            [("PID", int), ("Process", str), ("Argc", int), ("Arguments", str)],
            self._generator(
                list_tasks(self.context, self.config["kernel"], filter_func=filter_func)
            ),
        )
