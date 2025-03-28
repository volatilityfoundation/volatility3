# This file is Copyright 2024 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

import logging
import re
from typing import List

from volatility3.framework import interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.interfaces import plugins
from volatility3.framework.layers import scanners
from volatility3.framework.renderers import format_hints

vollog = logging.getLogger(__name__)


class RegExScan(plugins.PluginInterface):
    """Scans kernel memory using RegEx patterns."""

    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 0)
    MAXSIZE_DEFAULT = 128

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.TranslationLayerRequirement(
                name="primary",
                description="Memory layer for the kernel",
                architectures=["Intel32", "Intel64"],
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

    def _generator(self, regex_pattern):
        regex_pattern = bytes(regex_pattern, "UTF-8")
        vollog.debug(f"RegEx Pattern: {regex_pattern}")

        layer = self.context.layers[self.config["primary"]]
        for offset in layer.scan(
            context=self.context, scanner=scanners.RegExScanner(regex_pattern)
        ):
            result_data = layer.read(offset, self.MAXSIZE_DEFAULT, pad=True)

            # reapply the regex in order to extact just the match
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

            yield 0, (format_hints.Hex(offset), text_result, bytes_result)

    def run(self):
        return renderers.TreeGrid(
            [
                ("Offset", format_hints.Hex),
                ("Text", str),
                ("Hex", bytes),
            ],
            self._generator(self.config.get("pattern")),
        )
