# This file is Copyright 2024 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

import logging
import re
from typing import List

from volatility3.framework import renderers, interfaces
from volatility3.framework.configuration import requirements
from volatility3.framework.interfaces import plugins
from volatility3.framework.layers import scanners
from volatility3.framework.objects import utility
from volatility3.framework.renderers import format_hints
from volatility3.plugins.linux import pslist

vollog = logging.getLogger(__name__)


class VmaRegExScan(plugins.PluginInterface):
    """Scans all virtual memory areas for tasks using RegEx."""

    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 2)

    MAXSIZE_DEFAULT = 128

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        # Since we're calling the plugin, make sure we have the plugin's requirements
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Linux kernel",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.VersionRequirement(
                name="pslist", component=pslist.PsList, version=(4, 0, 0)
            ),
            requirements.ListRequirement(
                name="pid",
                description="Filter on specific process IDs",
                element_type=int,
                optional=True,
            ),
            requirements.StringRequirement(
                name="pattern", description="RegEx pattern", optional=False
            ),
            requirements.VersionRequirement(
                name="regex_scanner",
                component=scanners.RegExScanner,
                version=(1, 0, 0),
            ),
            requirements.IntRequirement(
                name="maxsize",
                description="Maximum size in bytes for displayed context",
                default=cls.MAXSIZE_DEFAULT,
                optional=True,
            ),
        ]

    def _generator(self, regex_pattern, tasks):
        regex_pattern = bytes(regex_pattern, "UTF-8")
        vollog.debug(f"RegEx Pattern: {regex_pattern}")

        for task in tasks:
            if not task.mm:
                continue
            name = utility.array_to_string(task.comm)

            # attempt to create a process layer for each task and skip those
            # that cannot (e.g. kernel threads)
            proc_layer_name = task.add_process_layer()
            if not proc_layer_name:
                continue

            # get the proc_layer object from the context
            proc_layer = self.context.layers[proc_layer_name]

            # get process sections for scanning
            sections = [
                (start, size) for (start, size) in task.get_process_memory_sections()
            ]

            for offset in proc_layer.scan(
                context=self.context,
                scanner=scanners.RegExScanner(regex_pattern),
                sections=sections,
                progress_callback=self._progress_callback,
            ):
                result_data = proc_layer.read(offset, self.MAXSIZE_DEFAULT, pad=True)

                # reapply the regex in order to extract just the match
                regex_result = re.match(regex_pattern, result_data)

                if regex_result:
                    # the match is within the results_data (e.g. it fits within MAXSIZE_DEFAULT)
                    # extract just the match itself
                    regex_match = regex_result.group(0)
                    text_result = str(regex_match, encoding="UTF-8", errors="replace")
                    bytes_result = regex_match
                else:
                    # the match is not with the results_data (e.g. it doesn't fit within MAXSIZE_DEFAULT)
                    text_result = str(result_data, encoding="UTF-8", errors="replace")
                    bytes_result = result_data

                user_pid = task.tgid
                yield (
                    0,
                    (
                        user_pid,
                        name,
                        format_hints.Hex(offset),
                        text_result,
                        bytes_result,
                    ),
                )

    def run(self):
        filter_func = pslist.PsList.create_pid_filter(self.config.get("pid", None))

        return renderers.TreeGrid(
            [
                ("PID", int),
                ("Process", str),
                ("Offset", format_hints.Hex),
                ("Text", str),
                ("Hex", bytes),
            ],
            self._generator(
                self.config.get("pattern"),
                pslist.PsList.list_tasks(
                    self.context, self.config["kernel"], filter_func=filter_func
                ),
            ),
        )
