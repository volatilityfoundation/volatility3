# This file is Copyright 2022 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

import logging
from typing import Generator, Iterator, List, Tuple

from volatility3.framework import interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.objects import utility
from volatility3.framework.renderers import format_hints
from volatility3.plugins.windows import pslist, vadinfo

vollog = logging.getLogger(__name__)


class VadWalk(interfaces.plugins.PluginInterface):
    """Walk the VAD tree."""

    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Windows kernel",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.VersionRequirement(
                name="pslist", component=pslist.PsList, version=(3, 0, 0)
            ),
            requirements.VersionRequirement(
                name="vadinfo", component=vadinfo.VadInfo, version=(2, 0, 0)
            ),
            requirements.ListRequirement(
                name="pid",
                element_type=int,
                description="Process IDs to include (all other processes are excluded)",
                optional=True,
            ),
        ]

    def _generator(
        self, procs: Generator[interfaces.objects.ObjectInterface, None, None]
    ) -> Iterator[Tuple]:
        for proc in procs:
            for vad in vadinfo.VadInfo.list_vads(proc):
                if vad:
                    yield (
                        0,
                        (
                            proc.UniqueProcessId,
                            utility.array_to_string(proc.ImageFileName),
                            format_hints.Hex(vad.vol.offset),
                            format_hints.Hex(
                                vad.get_parent()
                                & self.context.layers[vad.vol.layer_name].address_mask
                            ),
                            format_hints.Hex(vad.get_left_child()),
                            format_hints.Hex(vad.get_right_child()),
                            format_hints.Hex(vad.get_start()),
                            format_hints.Hex(vad.get_end()),
                            vad.get_tag(),
                        ),
                    )

    def run(self) -> renderers.TreeGrid:
        filter_func = pslist.PsList.create_pid_filter(self.config.get("pid", None))

        return renderers.TreeGrid(
            [
                ("PID", int),
                ("Process", str),
                ("Offset", format_hints.Hex),
                ("Parent", format_hints.Hex),
                ("Left", format_hints.Hex),
                ("Right", format_hints.Hex),
                ("Start", format_hints.Hex),
                ("End", format_hints.Hex),
                ("Tag", str),
            ],
            self._generator(
                pslist.PsList.list_processes(
                    context=self.context,
                    kernel_module_name=self.config["kernel"],
                    filter_func=filter_func,
                )
            ),
        )
