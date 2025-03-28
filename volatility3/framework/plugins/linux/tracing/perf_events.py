# This file is Copyright 2025 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
import logging
from typing import List, Tuple, Generator, Optional

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
                name="pslist", plugin=pslist.PsList, version=(4, 0, 0)
            ),
        ]

    @classmethod
    def list_perf_events(cls, context, vmlinux_module_name: str) -> Generator[
        Tuple[
            interfaces.objects.ObjectInterface,
            interfaces.objects.ObjectInterface,
            Optional[str],
            Optional[str],
            Optional[str],
            Optional[int],
        ],
        None,
        None,
    ]:
        """
        Walks the `perf_event_list` of each `task_struct` and reports valid event structures found
        This plugin is one of several to detect eBPF based malware

        Args:
            context:
            vmlinux_module_name:

        Returns:
            A tuple of the task struct, performance event object, event name, program name, full name, and program address
        """
        vmlinux = context.modules[vmlinux_module_name]

        if not vmlinux.has_type("perf_event") or not vmlinux.get_type(
            "perf_event"
        ).has_member("owner_entry"):
            vollog.warning(
                "This kernel does not have performance events enabled (CONFIG_PERF_EVENTS). Cannot proceed."
            )
            return

        for task in pslist.PsList.list_tasks(
            context, vmlinux_module_name, include_threads=True
        ):

            # walk the list of perf_event entries for this process
            for event in task.perf_event_list.to_list(
                vmlinux.symbol_table_name + constants.BANG + "perf_event", "owner_entry"
            ):
                # if the names are smeared then bail
                try:
                    event_name = utility.pointer_to_string(event.pmu.name, count=64)
                    try:
                        full_name = utility.array_to_string(
                            event.prog.aux.ksym.name, count=512
                        )
                    except AttributeError:
                        full_name = None

                    program_name = utility.array_to_string(event.prog.aux.name)
                except exceptions.InvalidAddressException:
                    continue

                # if the kernel has the prog member then ensure it is not 0
                if hasattr(event, "prog"):
                    program_address = event.prog
                    if program_address == 0:
                        continue

                else:
                    program_address = None

                yield task, event_name, program_name, full_name, program_address

    def _generator(self):
        for (
            task,
            event_name,
            program_name,
            full_name,
            program_address,
        ) in self.list_perf_events(self.context, self.config["kernel"]):
            task_name = utility.array_to_string(task.comm)

            # We at least need one useful string...
            if event_name is None and program_name is None and full_name is None:
                continue

            if program_address is not None:
                program_address = format_hints.Hex(program_address)
            else:
                program_address = renderers.NotAvailableValue()

            yield (
                0,
                (
                    task.pid,
                    task_name,
                    event_name or renderers.NotAvailableValue(),
                    program_name or renderers.NotAvailableValue(),
                    full_name or renderers.NotAvailableValue(),
                    program_address,
                ),
            )

    def run(self) -> renderers.TreeGrid:
        return renderers.TreeGrid(
            [
                ("PID", int),
                ("Process", str),
                ("Event", str),
                ("Short Program Name", str),
                ("Full Name", str),
                ("Address", format_hints.Hex),
            ],
            self._generator(),
        )
