# This file is Copyright 2023 Volatility Foundation and licensed under the Volatility Software License 1.0
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
    _version = (1, 0, 0)

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
            requirements.PluginRequirement(
                name="pslist", plugin=pslist.PsList, version=(2, 0, 0)
            ),
            requirements.PluginRequirement(
                name="yarascan", plugin=yarascan.YaraScan, version=(3, 0, 0)
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

            for start, end in self.get_vma_maps(task):
                data = proc_layer.read(start, end - start, True)
                if not yarascan.YaraScan._yara_x:
                    for match in rules.match(data=data):
                        if yarascan.YaraScan.yara_returns_instances():
                            for match_string in match.strings:
                                for instance in match_string.instances:
                                    yield 0, (
                                        format_hints.Hex(instance.offset + start),
                                        task.tgid,
                                        match.rule,
                                        match_string.identifier,
                                        format_hints.HexBytes(data[
                                            max(
                                                instance.offset
                                                - self.config["context_before"],
                                                0,
                                            ) : instance.offset
                                            + self.config["context_after"]
                                        ]),
                                    )
                        else:
                            for offset, name, value in match.strings:
                                yield 0, (
                                    format_hints.Hex(offset + start),
                                    task.tgid,
                                    match.rule,
                                    name,
                                    format_hints.HexBytes(data[
                                        max(
                                            offset - self.config["context_before"], 0
                                        ) : offset
                                        + self.config["context_after"]
                                    ]),
                                )
                else:
                    for match in rules.scan(data).matching_rules:
                        for match_string in match.patterns:
                            for instance in match_string.matches:
                                yield 0, (
                                    format_hints.Hex(instance.offset + start),
                                    task.tgid,
                                    f"{match.namespace}.{match.identifier}",
                                    match_string.identifier,
                                    format_hints.HexBytes(data[
                                        max(
                                            instance.offset
                                            - self.config["context_before"],
                                            0,
                                        ) : instance.offset
                                        + self.config["context_after"]
                                    ]),
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
                ("Value", format_hints.HexBytes),
            ],
            self._generator(),
        )
