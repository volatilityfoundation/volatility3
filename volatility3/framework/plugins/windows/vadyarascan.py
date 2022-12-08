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
    _version = (1, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Windows kernel",
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

        for task in pslist.PsList.list_processes(
            context=self.context,
            layer_name=kernel.layer_name,
            symbol_table=kernel.symbol_table_name,
            filter_func=filter_func,
        ):
            layer_name = task.add_process_layer()
            layer = self.context.layers[layer_name]
            for offset, rule_name, name, value in layer.scan(
                context=self.context,
                scanner=yarascan.YaraScanner(rules=rules),
                sections=self.get_vad_maps(task),
            ):
                yield 0, (
                    format_hints.Hex(offset),
                    task.UniqueProcessId,
                    rule_name,
                    name,
                    value,
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
            An iterable of tuples containing start and end addresses for each descriptor
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
