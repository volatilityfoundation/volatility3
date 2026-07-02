# This file is Copyright 2023 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

import logging
from typing import Iterable, List, Tuple

from volatility3.framework import interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.renderers import format_hints
from volatility3.plugins import yarascan
from volatility3.plugins.linux import pslist

vollog = logging.getLogger(__name__)


class VmaYaraScan(interfaces.plugins.PluginInterface):
    """Scans all virtual memory areas for tasks using yara."""

    _required_framework_version = (2, 22, 0)
    _version = (1, 0, 4)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        # create a list of requirements for vmayarascan
        vmayarascan_requirements = [
            requirements.ListRequirement(
                name="pid",
                element_type=int,
                description="Process IDs to include (all other processes are excluded)",
                optional=True,
            ),
            requirements.VersionRequirement(
                name="pslist", component=pslist.PsList, version=(4, 0, 0)
            ),
            requirements.VersionRequirement(
                name="yarascan", component=yarascan.YaraScan, version=(2, 0, 0)
            ),
            requirements.VersionRequirement(
                name="yarascanner", component=yarascan.YaraScanner, version=(2, 0, 0)
            ),
            requirements.ModuleRequirement(
                name="kernel",
                description="Linux kernel",
                architectures=["Intel32", "Intel64"],
            ),
        ]

        # get base yarascan requirements for command line options
        yarascan_requirements = yarascan.YaraScan.get_yarascan_option_requirements()

        # return the combined requirements
        return yarascan_requirements + vmayarascan_requirements

    def _generator(self):
        # use yarascan to parse the yara options provided and create the rules
        rules = yarascan.YaraScan.process_yara_options(dict(self.config))

        sanity_check = 1024 * 1024 * 1024  # 1 GB

        # filter based on the pid option if provided
        filter_func = pslist.PsList.create_pid_filter(self.config.get("pid", None))
        for task in pslist.PsList.list_tasks(
            context=self.context,
            vmlinux_module_name=self.config["kernel"],
            filter_func=filter_func,
        ):
            # attempt to create a process layer for each task and skip those
            # that cannot (e.g. kernel threads)
            proc_layer_name = task.add_process_layer()
            if not proc_layer_name:
                continue

            # get the proc_layer object from the context
            proc_layer = self.context.layers[proc_layer_name]

            max_vma_size = 0
            vma_maps_to_scan = []
            for start, size in self.get_vma_maps(task):
                if size > sanity_check:
                    vollog.debug(
                        f"VMA at 0x{start:x} over sanity-check size, not scanning"
                    )
                    continue
                max_vma_size = max(max_vma_size, size)
                vma_maps_to_scan.append((start, size))

            if not vma_maps_to_scan:
                vollog.warning(f"No VMAs were found for task {task.tgid}, not scanning")
                continue

            scanner = yarascan.YaraScanner(rules=rules)
            scanner.chunk_size = max_vma_size

            # scan the VMA data (in one contiguous block) with the yarascanner
            for start, size in vma_maps_to_scan:
                for offset, rule_name, name, value in scanner(
                    proc_layer.read(start, size, pad=True), start
                ):
                    layer_data = renderers.LayerData(
                        context=self.context,
                        offset=offset,
                        layer_name=proc_layer.name,
                        length=len(value),
                    )
                    yield (
                        0,
                        (
                            format_hints.Hex(offset),
                            task.tgid,
                            rule_name,
                            name,
                            layer_data,
                        ),
                    )

    @classmethod
    def get_vma_maps(
        cls,
        task: interfaces.objects.ObjectInterface,
    ) -> Iterable[Tuple[int, int]]:
        """Creates a map of start/end addresses for each virtual memory area in a task.

        Args:
            task: The task object of which to read the vmas from

        Returns:
            An iterable of tuples containing start and end addresses for each descriptor
        """
        if task.mm:
            for vma in task.mm.get_vma_iter():
                vm_size = vma.vm_end - vma.vm_start
                yield (vma.vm_start, vm_size)

    def run(self):
        return renderers.TreeGrid(
            [
                ("Offset", format_hints.Hex),
                ("PID", int),
                ("Rule", str),
                ("Component", str),
                ("Value", renderers.LayerData),
            ],
            self._generator(),
        )
