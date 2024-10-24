# This file is Copyright 2024 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
import logging
from typing import List, Callable, Tuple, Iterable

from volatility3.framework import renderers, interfaces, constants, exceptions
from volatility3.framework.renderers import format_hints
from volatility3.framework.configuration import requirements
from volatility3.framework.interfaces import plugins
from volatility3.framework.objects import utility
from volatility3.plugins.linux import pslist

vollog = logging.getLogger(__name__)


class PerfEvents(plugins.PluginInterface):
    """Lists performance events for each process."""

    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Linux kernel",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.PluginRequirement(
                name="pslist", plugin=pslist.PsList, version=(2, 0, 0)
            ),
            requirements.ListRequirement(
                name="pid",
                description="Filter on specific process IDs",
                element_type=int,
                optional=True,
            ),
        ]

    def _generator(self):
        """
        Walks the `perf_event_list` of each `task_struct` and reports valid event structures found
        This plugin is one of several to detect eBPF based malware
        """
        vmlinux_module_name = self.config["kernel"]
        vmlinux = self.context.modules[vmlinux_module_name]

        if not vmlinux.has_type("perf_event") or not vmlinux.get_type(
            "perf_event"
        ).has_member("owner_entry"):
            vollog.warning(
                "This kernel does not have performance events enabled (CONFIG_PERF_EVENTS). Cannot proceed."
            )
            return

        for task in pslist.PsList.list_tasks(
            self.context, vmlinux_module_name, include_threads=True
        ):
            task_name = utility.array_to_string(task.comm)

            # walk the list of perf_event entries for this process
            for event in task.perf_event_list.to_list(
                vmlinux.symbol_table_name + constants.BANG + "perf_event", "owner_entry"
            ):
                # if the names are smeared then bail
                try:
                    event_name = utility.pointer_to_string(event.pmu.name, count=64)
                    program_name = utility.array_to_string(event.prog.aux.name)
                except exceptions.InvalidAddressException:
                    continue

                # if the kernel has the prog member then ensure it is not 0
                if hasattr(event, "prog"):
                    program_address = event.prog
                    if program_address == 0:
                        continue

                    program_address = format_hints.Hex(program_address)

                else:
                    program_address = renderers.NotAvailableValue()

                yield (
                    0,
                    (task.pid, task_name, event_name, program_name, program_address),
                )

    def run(self) -> renderers.TreeGrid:
        return renderers.TreeGrid(
            [
                ("PID", int),
                ("Process", str),
                ("Event Name", str),
                ("Program Name", str),
                ("Address", format_hints.Hex),
            ],
            self._generator(),
        )
