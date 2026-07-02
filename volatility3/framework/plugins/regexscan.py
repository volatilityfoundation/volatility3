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
            requirements.VersionRequirement(
                name="regex_scanner",
                component=scanners.RegExScanner,
                version=(1, 0, 0),
            ),
        ]

    def _generator(self, context, layer_name, pattern, maxsize):
        layer = self.context.layers[layer_name]
        vollog.debug(f"RegEx Pattern: {pattern}")

        # Convert string pattern to bytes for RegExScanner
        pattern_bytes = pattern.encode("utf-8")

        # Compile the pattern here to ensure consistency
        try:
            compiled_pattern = re.compile(pattern_bytes)
        except re.error as e:
            vollog.error(f"Invalid regex pattern: {e}")
            raise ValueError(f"Invalid regex pattern: {e}")

        for offset in layer.scan(
            context=context, scanner=scanners.RegExScanner(pattern_bytes)
        ):
            result_data = layer.read(offset, maxsize, pad=True)

            # reapply the regex in order to extract just the match
            regex_result = compiled_pattern.search(result_data)

            if regex_result:
                # the match is within the results_data (e.g. it fits within maxsize)
                # extract just the match itself
                regex_match = regex_result.group(0)
                text_result = str(regex_match, encoding="UTF-8", errors="replace")
                bytes_result = regex_match
            else:
                # the match is not with the results_data (e.g. it doesn't fit within maxsize)
                text_result = str(result_data, encoding="UTF-8", errors="replace")
                bytes_result = result_data

            yield 0, (format_hints.Hex(offset), text_result, bytes_result)

    def run(self):
        pattern = self.config.get("pattern")
        maxsize = self.config.get("maxsize", self.MAXSIZE_DEFAULT)
        layer_name = self.config["primary"]
        context = self.context

        return renderers.TreeGrid(
            [
                ("Offset", format_hints.Hex),
                ("Text", str),
                ("Hex", bytes),
            ],
            self._generator(context, layer_name, pattern, maxsize),
        )
