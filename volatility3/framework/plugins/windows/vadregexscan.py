# This file is Copyright 2024 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

import logging
import re
from typing import List

from volatility3.framework import renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.interfaces import plugins, configuration
from volatility3.framework.layers import scanners
from volatility3.framework.renderers import format_hints
from volatility3.plugins.windows import pslist

vollog = logging.getLogger(__name__)


class VadRegExScan(plugins.PluginInterface):
    """Scans all virtual memory areas for tasks using RegEx."""

    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 0)
    MAXSIZE_DEFAULT = 128

    @classmethod
    def get_requirements(cls) -> List[configuration.RequirementInterface]:
        # Since we're calling the plugin, make sure we have the plugin's requirements
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Windows kernel",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.VersionRequirement(
                name="pslist", component=pslist.PsList, version=(3, 0, 0)
            ),
            requirements.ListRequirement(
                name="pid",
                description="Filter on specific process IDs",
                element_type=int,
                optional=True,
            ),
            requirements.VersionRequirement(
                name="regex_scanner",
                component=scanners.RegExScanner,
                version=(1, 0, 0),
            ),
            requirements.StringRequirement(
                name="pattern", description="RegEx pattern", optional=False
            ),
            requirements.IntRequirement(
                name="maxsize",
                description="Maximum size in bytes for displayed context",
                default=cls.MAXSIZE_DEFAULT,
                optional=True,
            ),
        ]

    def _generator(self, regex_pattern, procs):
        regex_pattern = bytes(regex_pattern, "UTF-8")
        vollog.debug(f"RegEx Pattern: {regex_pattern}")

        for proc in procs:
            # attempt to create a process layer for each proc
            proc_layer_name = proc.add_process_layer()
            if not proc_layer_name:
                continue

            # get the proc_layer object from the context
            proc_layer = self.context.layers[proc_layer_name]

            # get process sections for scanning
            sections = []
            for vad in proc.get_vad_root().traverse():
                base = vad.get_start()
                if vad.get_size():
                    sections.append((base, vad.get_size()))

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

                proc_id = proc.UniqueProcessId
                process_name = proc.ImageFileName.cast(
                    "string",
                    max_length=proc.ImageFileName.vol.count,
                    errors="replace",
                )
                yield (
                    0,
                    (
                        proc_id,
                        process_name,
                        format_hints.Hex(offset),
                        text_result,
                        bytes_result,
                    ),
                )

    def run(self):
        filter_func = pslist.PsList.create_pid_filter(self.config.get("pid", None))
        procs = pslist.PsList.list_processes(
            context=self.context,
            kernel_module_name=self.config["kernel"],
            filter_func=filter_func,
        )
        return renderers.TreeGrid(
            [
                ("PID", int),
                ("Process", str),
                ("Offset", format_hints.Hex),
                ("Text", str),
                ("Hex", bytes),
            ],
            self._generator(self.config.get("pattern"), procs),
        )
