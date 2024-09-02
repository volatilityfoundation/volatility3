# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

import logging
from typing import Iterable, List, Tuple

from volatility3.framework import interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.renderers import format_hints
from volatility3.plugins import yarascan
from volatility3.plugins.windows import pslist

vollog = logging.getLogger(__name__)


class VadYaraScan(interfaces.plugins.PluginInterface):
    """Scans all the Virtual Address Descriptor memory maps using yara."""

    _required_framework_version = (2, 4, 0)
    _version = (1, 1, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        # create a list of requirements for vadyarascan
        vadyarascan_requirements = [
            requirements.ModuleRequirement(
                name="kernel",
                description="Windows kernel",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.PluginRequirement(
                name="pslist", plugin=pslist.PsList, version=(2, 0, 0)
            ),
            requirements.PluginRequirement(
                name="yarascan", plugin=yarascan.YaraScan, version=(2, 0, 0)
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
        kernel = self.context.modules[self.config["kernel"]]

        rules = yarascan.YaraScan.process_yara_options(dict(self.config))

        filter_func = pslist.PsList.create_pid_filter(self.config.get("pid", None))

        sanity_check = 1024 * 1024 * 1024  # 1 GB

        for task in pslist.PsList.list_processes(
            context=self.context,
            layer_name=kernel.layer_name,
            symbol_table=kernel.symbol_table_name,
            filter_func=filter_func,
        ):
            layer_name = task.add_process_layer()
            layer = self.context.layers[layer_name]
            for start, size in self.get_vad_maps(task):
                if size > sanity_check:
                    vollog.warn(
                        f"VAD at 0x{start:x} over sanity-check size, not scanning"
                    )
                    continue

                data = layer.read(start, size, True)
                if not yarascan.YaraScan._yara_x:
                    for match in rules.match(data=data):
                        if yarascan.YaraScan.yara_returns_instances():
                            for match_string in match.strings:
                                for instance in match_string.instances:
                                    yield 0, (
                                        format_hints.Hex(instance.offset + start),
                                        task.UniqueProcessId,
                                        match.rule,
                                        match_string.identifier,
                                        instance.matched_data,
                                    )
                        else:
                            for offset, name, value in match.strings:
                                yield 0, (
                                    format_hints.Hex(offset + start),
                                    task.UniqueProcessId,
                                    match.rule,
                                    name,
                                    value,
                                )
                else:
                    for match in rules.scan(data).matching_rules:
                        for match_string in match.patterns:
                            for instance in match_string.matches:
                                yield 0, (
                                    format_hints.Hex(instance.offset + start),
                                    task.UniqueProcessId,
                                    f"{match.namespace}.{match.identifier}",
                                    match_string.identifier,
                                    data[
                                        instance.offset : instance.offset
                                        + instance.length
                                    ],
                                )

    @staticmethod
    def get_vad_maps(
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
                ("Rule", str),
                ("Component", str),
                ("Value", bytes),
            ],
            self._generator(),
        )
