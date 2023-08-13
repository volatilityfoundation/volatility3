# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

from volatility3.framework import renderers, interfaces
from volatility3.framework.configuration import requirements
from volatility3.framework.objects import utility
from volatility3.framework.renderers import format_hints
from volatility3.plugins.mac import pslist


class Maps(interfaces.plugins.PluginInterface):
    """Lists process memory ranges that potentially contain injected code."""

    _required_framework_version = (2, 0, 0)

    @classmethod
    def get_requirements(cls):
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

    def _generator(self, tasks):
        for task in tasks:
            process_name = utility.array_to_string(task.p_comm)
            process_pid = task.p_pid

            for vma in task.get_map_iter():
                path = vma.get_path(
                    self.context,
                    self.context.modules[self.config["kernel"]].symbol_table_name,
                )
                if path == "":
                    path = vma.get_special_path()

                yield (
                    0,
                    (
                        process_pid,
                        process_name,
                        format_hints.Hex(vma.links.start),
                        format_hints.Hex(vma.links.end),
                        vma.get_perms(),
                        path,
                    ),
                )

    def run(self):
        filter_func = pslist.PsList.create_pid_filter(self.config.get("pid", None))
        list_tasks = pslist.PsList.get_list_tasks(
            self.config.get("pslist_method", pslist.PsList.pslist_methods[0])
        )

        return renderers.TreeGrid(
            [
                ("PID", int),
                ("Process", str),
                ("Start", format_hints.Hex),
                ("End", format_hints.Hex),
                ("Protection", str),
                ("Map Name", str),
            ],
            self._generator(
                list_tasks(self.context, self.config["kernel"], filter_func=filter_func)
            ),
        )
