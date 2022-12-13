# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

from typing import Iterable, List, Tuple

from volatility3.framework import interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.renderers import format_hints
from volatility3.plugins import yarascan
from volatility3.plugins.linux import pslist

class VmaYaraScan(interfaces.plugins.PluginInterface):
    """Scans all virtual memory areas for tasks using yara."""

    _required_framework_version = (2, 4, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Linux kernel",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.BooleanRequirement(
                name="wide",
                description="Match wide (unicode) strings",
                default=False,
                optional=True,
            ),
            requirements.StringRequirement(
                name="yara_rules", description="Yara rules (as a string)", optional=True
            ),
            requirements.URIRequirement(
                name="yara_file", description="Yara rules (as a file)", optional=True
            ),
            # This additional requirement is to follow suit with upstream, who feel that compiled rules could potentially be used to execute malicious code
            # As such, there's a separate option to run compiled files, as happened with yara-3.9 and later
            requirements.URIRequirement(
                name="yara_compiled_file",
                description="Yara compiled rules (as a file)",
                optional=True,
            ),
            requirements.IntRequirement(
                name="max_size",
                default=0x40000000,
                description="Set the maximum size (default is 1GB)",
                optional=True,
            ),
            requirements.PluginRequirement(
                name="pslist", plugin=pslist.PsList, version=(2, 0, 0)
            ),
            requirements.VersionRequirement(
                name="yarascanner", component=yarascan.YaraScanner, version=(2, 0, 0)
            ),
            requirements.ListRequirement(
                name="pid",
                element_type=int,
                description="Process IDs to include (all other processes are excluded)",
                optional=True,
            ),
        ]

    def _generator(self):
        kernel = self.context.modules[self.config["kernel"]]

        rules = yarascan.YaraScan.process_yara_options(dict(self.config))

        filter_func = pslist.PsList.create_pid_filter(self.config.get("pid", None))
        for task in pslist.PsList.list_tasks(
            context=self.context,
            vmlinux_module_name=self.config["kernel"],
            filter_func=filter_func,
        ):
            proc_layer_name = task.add_process_layer()
            if not proc_layer_name:
                continue

            proc_layer = self.context.layers[proc_layer_name]
            for offset, rule_name, name, value in proc_layer.scan(
                context=self.context,
                scanner=yarascan.YaraScanner(rules=rules),
                sections=self.get_vma_maps(task),
            ):
                yield 0, (
                    format_hints.Hex(offset),
                    task.tgid,
                    rule_name,
                    name,
                    value,
                )

    @staticmethod
    def get_vma_maps(
        task: interfaces.objects.ObjectInterface,
    ) -> Iterable[Tuple[int, int]]:
        """Creates a map of start/end addresses for each virtual memory area in a task.

        Args:
            task: The task object of which to read the vmas from

        Returns:
            An iterable of tuples containing start and end addresses for each descriptor
        """
        if task.mm:
            for vma in task.mm.get_mmap_iter():
                vm_size = vma.vm_end - vma.vm_start
                yield (vma.vm_start, vm_size)

    def run(self):
        return renderers.TreeGrid(
            [
                ("Offset", format_hints.Hex),
                ("PID", int),
                ("Rule", str),
                ("Component", str),
                ("Value", bytes),
            ],
            self._generator(),
        )
