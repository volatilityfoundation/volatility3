# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

import json
import logging
from typing import List

from volatility3.framework import renderers, interfaces
from volatility3.framework.configuration import requirements
from volatility3.framework.interfaces import plugins

vollog = logging.getLogger(__name__)


class ConfigWriter(plugins.PluginInterface):
    """Runs the automagics and both prints and outputs configuration in the
    output directory."""

    _required_framework_version = (2, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.TranslationLayerRequirement(
                name="primary",
                description="Memory layer for the kernel",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.BooleanRequirement(
                name="extra",
                description="Outputs whole configuration tree",
                default=False,
                optional=True,
            ),
        ]

    def _generator(self):
        filename = "config.json"
        config = dict(self.build_configuration())
        if self.config.get("extra", False):
            vollog.debug(
                "Outputting additional information, this will NOT work with the -c option"
            )
            config = dict(self.context.config)
            filename = "config.extra"
        try:
            with self.open(filename) as file_data:
                file_data.write(
                    bytes(
                        json.dumps(config, sort_keys=True, indent=2),
                        "raw_unicode_escape",
                    )
                )
        except Exception as excp:
            vollog.warning(f"Unable to JSON encode configuration: {excp}")

        for k, v in config.items():
            yield (0, (k, json.dumps(v)))

    def run(self):
        return renderers.TreeGrid([("Key", str), ("Value", str)], self._generator())
