# This file is Copyright 2026 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

import logging
from typing import List

from volatility3.framework import interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.layers import crash
from volatility3.framework.renderers import format_hints

vollog = logging.getLogger(__name__)


class CrashModules(interfaces.plugins.PluginInterface, crash.MiniKernelDumpMixin):
    """Lists modules recorded in a Windows mini kernel dump."""

    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.TranslationLayerRequirement(
                name="primary",
                description="Memory layer for the kernel",
                architectures=["Intel64"],
            ),
        ]

    def _generator(self):
        crash_layer = self._get_crash_layer(
            self.context, self.config.get("primary", None)
        )
        if crash_layer is None:
            vollog.error("This plugin requires a Windows mini kernel crash dump")
            raise ValueError("This plugin requires a Windows mini kernel crash dump")

        for (
            entry_offset,
            image_base,
            image_size,
            path,
            checksum,
            timestamp,
        ) in crash_layer.iter_mini_kernel_modules():
            yield (
                0,
                (
                    format_hints.Hex(entry_offset),
                    format_hints.Hex(image_base),
                    format_hints.Hex(image_size),
                    crash_layer.mini_kernel_module_name(path),
                    path,
                    format_hints.Hex(checksum),
                    format_hints.Hex(timestamp),
                ),
            )

    def run(self):
        return renderers.TreeGrid(
            [
                ("Offset", format_hints.Hex),
                ("Base", format_hints.Hex),
                ("Size", format_hints.Hex),
                ("Name", str),
                ("Path", str),
                ("CheckSum", format_hints.Hex),
                ("TimeDateStamp", format_hints.Hex),
            ],
            self._generator(),
        )
