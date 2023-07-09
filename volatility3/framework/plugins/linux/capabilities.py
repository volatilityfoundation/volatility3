# This file is Copyright 2023 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

import logging
from dataclasses import dataclass, astuple, fields
from typing import Iterable, List, Tuple

from volatility3.framework import interfaces, renderers, exceptions
from volatility3.framework.constants.linux import CAP_FULL
from volatility3.framework.configuration import requirements
from volatility3.framework.interfaces import plugins
from volatility3.framework.objects import utility
from volatility3.framework.symbols.linux import extensions
from volatility3.plugins.linux import pslist

vollog = logging.getLogger(__name__)


@dataclass
class TaskData:
    """Stores basic information about a task"""

    comm: str
    pid: int
    tgid: int
    ppid: int
    euid: int


@dataclass
class CapabilitiesData:
    """Stores each set of capabilties for a task"""

    cap_inheritable: interfaces.objects.ObjectInterface
    cap_permitted: interfaces.objects.ObjectInterface
    cap_effective: interfaces.objects.ObjectInterface
    cap_bset: interfaces.objects.ObjectInterface
    cap_ambient: interfaces.objects.ObjectInterface

    def astuple(self) -> Tuple:
        """Returns a shallow copy of the capability sets in a tuple.

        Otherwise, when dataclasses.astuple() performs a deep-copy recursion on
        ObjectInterface will take a substantial amount of time.
        """
        return tuple(getattr(self, field.name) for field in fields(self))


class Capabilities(plugins.PluginInterface):
    """Lists process capabilities"""

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
                name="pids",
                description="Filter on specific process IDs.",
                element_type=int,
                optional=True,
            ),
        ]

    def _check_capabilities_support(
        self,
        context: interfaces.context.ContextInterface,
        vmlinux_module_name: str,
    ):
        """Checks that the framework supports at least as much capabilities as
        the kernel being analysed. Otherwise, it shows a warning for the
        developers.
        """

        vmlinux = context.modules[vmlinux_module_name]

        try:
            kernel_cap_last_cap = vmlinux.object_from_symbol(symbol_name="cap_last_cap")
        except exceptions.SymbolError:
            # It should be a kernel < 3.2
            return

        vol2_last_cap = extensions.kernel_cap_struct.get_last_cap_value()
        if kernel_cap_last_cap > vol2_last_cap:
            vollog.warning(
                "Developers: The supported Linux capabilities of this plugin are outdated for this kernel"
            )

    @staticmethod
    def _decode_cap(cap: interfaces.objects.ObjectInterface) -> str:
        """Returns a textual representation of the capability set.
        The format is a comma-separated list of capabilitites. In order to
        summarize the output and if all the capabilities are enabled, instead of
        the individual capabilities, the special name "all" will be shown.

        Args:
            cap: Kernel capability object. Usually a 'kernel_cap_struct' struct

        Returns:
            str: A string with a comma separated list of decoded capabilities
        """
        if isinstance(cap, renderers.NotAvailableValue):
            return cap

        cap_value = cap.get_capabilities()
        if not cap_value:
            return ""

        if cap_value == CAP_FULL:
            return "all"

        return ", ".join(cap.enumerate_capabilities())

    @classmethod
    def get_task_capabilities(
        cls, task: interfaces.objects.ObjectInterface
    ) -> Tuple[TaskData, CapabilitiesData]:
        """Returns a dict with the task basic information along with its capabilities

        Args:
            task: A task object from where to get the fields.

        Returns:
            A tuple with the task basic information and its capabilities
        """
        task_data = TaskData(
            comm=utility.array_to_string(task.comm),
            pid=int(task.pid),
            tgid=int(task.tgid),
            ppid=int(task.parent.pid),
            euid=int(task.cred.euid),
        )

        task_cred = task.real_cred
        capabilities_data = CapabilitiesData(
            cap_inheritable=task_cred.cap_inheritable,
            cap_permitted=task_cred.cap_permitted,
            cap_effective=task_cred.cap_effective,
            cap_bset=task_cred.cap_bset,
            cap_ambient=renderers.NotAvailableValue(),
        )

        # Ambient capabilities were added in kernels 4.3.6
        if task_cred.has_member("cap_ambient"):
            capabilities_data.cap_ambient = task_cred.cap_ambient

        return task_data, capabilities_data

    @classmethod
    def get_tasks_capabilities(
        cls, tasks: List[interfaces.objects.ObjectInterface]
    ) -> Iterable[Tuple[TaskData, CapabilitiesData]]:
        """Yields a dict for each task containing the task's basic information along with its capabilities

        Args:
            tasks: An iterable with the tasks to process.

        Yields:
            A tuple for each task containing the task's basic information and its capabilities
        """
        for task in tasks:
            yield cls.get_task_capabilities(task)

    def _generator(
        self, tasks: Iterable[interfaces.objects.ObjectInterface]
    ) -> Iterable[Tuple[int, Tuple]]:
        for task_fields, capabilities_fields in self.get_tasks_capabilities(tasks):
            task_fields = astuple(task_fields)

            capabilities_text = tuple(
                self._decode_cap(cap) for cap in capabilities_fields.astuple()
            )

            yield 0, task_fields + capabilities_text

    def run(self):
        self._check_capabilities_support(self.context, self.config["kernel"])

        pids = self.config.get("pids")
        pid_filter = pslist.PsList.create_pid_filter(pids)
        tasks = pslist.PsList.list_tasks(
            self.context, self.config["kernel"], filter_func=pid_filter
        )

        columns = [
            ("Name", str),
            ("Tid", int),
            ("Pid", int),
            ("PPid", int),
            ("EUID", int),
            ("cap_inheritable", str),
            ("cap_permitted", str),
            ("cap_effective", str),
            ("cap_bounding", str),
            ("cap_ambient", str),
        ]

        return renderers.TreeGrid(columns, self._generator(tasks))
