# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

import logging
from typing import Iterable, List, Tuple
import datetime

from volatility3.framework import interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.renderers import format_hints
from volatility3.plugins import yarascan
from volatility3.plugins.windows import pslist

vollog = logging.getLogger(__name__)


class VadYaraScan(interfaces.plugins.PluginInterface):
    """Scans all the Virtual Address Descriptor memory maps using yara."""

    _required_framework_version = (2, 22, 0)
    _version = (1, 1, 4)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        # create a list of requirements for vadyarascan
        vadyarascan_requirements = [
            requirements.ModuleRequirement(
                name="kernel",
                description="Windows kernel",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.VersionRequirement(
                name="pslist", component=pslist.PsList, version=(3, 0, 0)
            ),
            requirements.VersionRequirement(
                name="yarascanner", component=yarascan.YaraScanner, version=(2, 0, 0)
            ),
            requirements.VersionRequirement(
                name="yarascan", component=yarascan.YaraScan, version=(2, 0, 0)
            ),
            requirements.ListRequirement(
                name="pid",
                element_type=int,
                description="Process IDs to include (all other processes are excluded)",
                optional=True,
            ),
        ]

        # get base yarascan requirements for command line options
        yarascan_requirements = yarascan.YaraScan.get_yarascan_option_requirements()

        # return the combined requirements
        return yarascan_requirements + vadyarascan_requirements

    def _generator(self):
        rules = yarascan.YaraScan.process_yara_options(dict(self.config))

        filter_func = pslist.PsList.create_pid_filter(self.config.get("pid", None))

        sanity_check = 1024 * 1024 * 1024  # 1 GB

        for task in pslist.PsList.list_processes(
            context=self.context,
            kernel_module_name=self.config["kernel"],
            filter_func=filter_func,
        ):
            layer_name = task.add_process_layer()
            layer = self.context.layers[layer_name]

            max_vad_size = 0
            vad_maps_to_scan = []

            for start, size in self.get_vad_maps(task):
                if size > sanity_check:
                    vollog.debug(
                        f"VAD at 0x{start:x} over sanity-check size, not scanning"
                    )
                    continue
                max_vad_size = max(max_vad_size, size)
                vad_maps_to_scan.append((start, size))

            if not vad_maps_to_scan:
                vollog.warning(
                    f"No VADs were found for task {task.UniqueProcessId}, not scanning"
                )
                continue

            scanner = yarascan.YaraScanner(rules=rules)
            scanner.chunk_size = max_vad_size

            # scan the VAD data (in one contiguous block) with the yarascanner
            for start, size in vad_maps_to_scan:
                for offset, rule_name, name, value in scanner(
                    layer.read(start, size, pad=True), start
                ):
                    layer_data = renderers.LayerData(
                        context=self.context,
                        offset=offset,
                        layer_name=layer.name,
                        length=len(value),
                    )
                    yield (
                        0,
                        (
                            format_hints.Hex(offset),
                            task.UniqueProcessId,
                            task.get_create_time(),
                            task.InheritedFromUniqueProcessId,
                            task.ImageFileName.cast(
                                "string",
                                max_length=task.ImageFileName.vol.count,
                                errors="replace",
                            ),
                            task.get_session_id(),
                            task.ActiveThreads,
                            rule_name,
                            name,
                            layer_data,
                        ),
                    )

    @classmethod
    def get_vad_maps(
        cls,
        task: interfaces.objects.ObjectInterface,
    ) -> Iterable[Tuple[int, int]]:
        """Creates a map of start/end addresses within a virtual address
        descriptor tree.

        Args:
            task: The EPROCESS object of which to traverse the vad tree

        Returns:
            An iterable of tuples containing start and size for each descriptor
        """
        vad_root = task.get_vad_root()
        for vad in vad_root.traverse():
            yield (vad.get_start(), vad.get_size())

    def run(self):
        return renderers.TreeGrid(
            [
                ("Offset", format_hints.Hex),
                ("PID", int),
                ("CreateTime", datetime.datetime),
                ("PPID", int),
                ("ImageFileName", str),
                ("SessionId", int),
                ("Threads", int),
                ("Rule", str),
                ("Component", str),
                ("Value", renderers.LayerData),
            ],
            self._generator(),
        )
