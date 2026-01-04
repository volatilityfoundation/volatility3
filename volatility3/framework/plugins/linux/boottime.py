# This file is Copyright 2024 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
import datetime
from typing import List, Tuple, Iterable


from volatility3.framework import interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.plugins import timeliner
from volatility3.plugins.linux import pslist


class Boottime(interfaces.plugins.PluginInterface, timeliner.TimeLinerInterface):
    """Shows the time the system was started"""

    _required_framework_version = (2, 11, 0)
    _version = (1, 0, 2)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Linux kernel",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.VersionRequirement(
                name="timeliner",
                component=timeliner.TimeLinerInterface,
                version=(1, 0, 0),
            ),
            requirements.VersionRequirement(
                name="pslist", component=pslist.PsList, version=(4, 0, 0)
            ),
        ]

    @classmethod
    def get_time_namespaces_bootime(
        cls,
        context: interfaces.context.ContextInterface,
        vmlinux_module_name: str,
    ) -> Iterable[Tuple[int, int, int, str, datetime.datetime]]:
        """Enumerates tasks' boot times based on their time namespaces.

        Args:
            context: The context to retrieve required elements (layers, symbol tables) from
            vmlinux_module_name: The name of the kernel module on which to operate
            pids: Pid list
            unique: Filter unique time namespaces

        Yields:
            A tuple with the fields to show in the plugin output.
        """
        time_namespace_ids = set()
        for task in pslist.PsList.list_tasks(context, vmlinux_module_name):
            time_namespace_id = task.get_time_namespace_id()
            # If it cannot get the time namespace i.e. kernels < 5.6, this still works
            # using None to just get the first tasks
            if time_namespace_id in time_namespace_ids:
                continue
            time_namespace_ids.add(time_namespace_id)
            boottime = task.get_boottime(root_time_namespace=False)

            fields = (
                time_namespace_id,
                boottime,
            )
            yield fields

    def _generator(self):
        for (
            time_namespace_id,
            boottime,
        ) in self.get_time_namespaces_bootime(
            self.context,
            self.config["kernel"],
        ):
            fields = [
                time_namespace_id or renderers.NotAvailableValue(),
                boottime,
            ]
            yield 0, fields

    def generate_timeline(self):
        for (
            time_namespace_id,
            boottime,
        ) in self.get_time_namespaces_bootime(
            self.context,
            self.config["kernel"],
        ):
            description = f"System boot time for time namespace {time_namespace_id}"

            yield description, timeliner.TimeLinerType.CREATED, boottime

    def run(self):
        columns = [
            ("TIME NS", int),
            ("Boot Time", datetime.datetime),
        ]
        return renderers.TreeGrid(columns, self._generator())
