# This file is Copyright 2023 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

import logging
from typing import Iterable, List, Tuple, Dict

from volatility3.framework import interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.interfaces import plugins
from volatility3.framework.objects import utility
from volatility3.framework.renderers import format_hints
from volatility3.framework.symbols.linux import extensions
from volatility3.plugins.linux import pslist

vollog = logging.getLogger(__name__)


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
            requirements.BooleanRequirement(
                name="inheritable",
                description="Show only inheritable capabilities in human-readable strings.",
                optional=True,
            ),
            requirements.BooleanRequirement(
                name="permitted",
                description="Show only permitted capabilities in human-readable strings.",
                optional=True,
            ),
            requirements.BooleanRequirement(
                name="effective",
                description="Show only effective capabilities in human-readable strings.",
                optional=True,
            ),
            requirements.BooleanRequirement(
                name="bounding",
                description="Show only bounding capabilities in human-readable strings.",
                optional=True,
            ),
            requirements.BooleanRequirement(
                name="ambient",
                description="Show only ambient capabilities in human-readable strings.",
                optional=True,
            ),
        ]

    def _check_capabilities_support(self):
        """Checks that the framework supports at least as much capabilities as
        the kernel being analysed. Otherwise, it shows a warning for the
        developers.
        """
        vmlinux = self.context.modules[self.config["kernel"]]

        kernel_cap_last_cap = vmlinux.object(
            object_type="int", offset=kernel_cap_last_cap
        )
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
        if cap_value == 0:
            return "-"

        CAP_FULL = 0xFFFFFFFF
        if cap_value == CAP_FULL:
            return "all"

        return ", ".join(cap.enumerate_capabilities())

    @classmethod
    def get_task_capabilities(cls, task: interfaces.objects.ObjectInterface) -> Dict:
        """Returns a dict with the task basic information along with its capabilities

        Args:
            task: A task object from where to get the fields.

        Returns:
            dict: A dict with the task basic information along with its capabilities
        """
        task_cred = task.real_cred
        fields = {
            "common": [
                utility.array_to_string(task.comm),
                int(task.pid),
                int(task.tgid),
                int(task.parent.pid),
                int(task.cred.euid),
            ],
            "capabilities": [
                task_cred.cap_inheritable,
                task_cred.cap_permitted,
                task_cred.cap_effective,
                task_cred.cap_bset,
            ],
        }

        # Ambient capabilities were added in kernels 4.3.6
        if task_cred.has_member("cap_ambient"):
            fields["capabilities"].append(task_cred.cap_ambient)
        else:
            fields["capabilities"].append(renderers.NotAvailableValue())

        return fields

    def get_tasks_capabilities(
        self, tasks: List[interfaces.objects.ObjectInterface]
    ) -> Iterable[Dict]:
        """Yields a dict for each task containing the task's basic information along with its capabilities

        Args:
            tasks: An iterable with the tasks to process.

        Yields:
            Iterable[Dict]: A dict for each task containing the task's basic information along with its capabilities
        """
        for task in tasks:
            if task.is_kernel_thread:
                continue

            yield self.get_task_capabilities(task)

    def _generator(
        self, tasks: Iterable[interfaces.objects.ObjectInterface]
    ) -> Iterable[Tuple[int, Tuple]]:
        for fields in self.get_tasks_capabilities(tasks):
            selected_fields = fields["common"]
            cap_inh, cap_prm, cap_eff, cap_bnd, cap_amb = fields["capabilities"]

            if self.config.get("inheritable"):
                selected_fields.append(self._decode_cap(cap_inh))
            elif self.config.get("permitted"):
                selected_fields.append(self._decode_cap(cap_prm))
            elif self.config.get("effective"):
                selected_fields.append(self._decode_cap(cap_eff))
            elif self.config.get("bounding"):
                selected_fields.append(self._decode_cap(cap_bnd))
            elif self.config.get("ambient"):
                selected_fields.append(self._decode_cap(cap_amb))
            else:
                # Raw values
                selected_fields.append(format_hints.Hex(cap_inh.get_capabilities()))
                selected_fields.append(format_hints.Hex(cap_prm.get_capabilities()))
                selected_fields.append(format_hints.Hex(cap_eff.get_capabilities()))
                selected_fields.append(format_hints.Hex(cap_bnd.get_capabilities()))

                # Ambient capabilities were added in kernels 4.3.6
                if isinstance(cap_amb, renderers.NotAvailableValue):
                    selected_fields.append(cap_amb)
                else:
                    selected_fields.append(format_hints.Hex(cap_amb.get_capabilities()))

            yield 0, selected_fields

    def run(self):
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
        ]

        if self.config.get("inheritable"):
            columns.append(("cap_inheritable", str))
        elif self.config.get("permitted"):
            columns.append(("cap_permitted", str))
        elif self.config.get("effective"):
            columns.append(("cap_effective", str))
        elif self.config.get("bounding"):
            columns.append(("cap_bounding", str))
        elif self.config.get("ambient"):
            columns.append(("cap_ambient", str))
        else:
            columns.append(("cap_inheritable", format_hints.Hex))
            columns.append(("cap_permitted", format_hints.Hex))
            columns.append(("cap_effective", format_hints.Hex))
            columns.append(("cap_bounding", format_hints.Hex))
            columns.append(("cap_ambient", format_hints.Hex))

        return renderers.TreeGrid(columns, self._generator(tasks))
