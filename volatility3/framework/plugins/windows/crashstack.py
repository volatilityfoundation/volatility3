# This file is Copyright 2026 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

import logging
from typing import List, Optional, Set, Tuple

from volatility3.framework import interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.layers import crash
from volatility3.framework.renderers import format_hints

vollog = logging.getLogger(__name__)


class CrashStack(interfaces.plugins.PluginInterface, crash.MiniKernelDumpMixin):
    """Scans a Windows mini kernel dump for module-relative stack references."""

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
            requirements.StringRequirement(
                name="name",
                description="module name/sub string",
                optional=True,
                default=None,
            ),
            requirements.IntRequirement(
                name="limit",
                description="maximum number of references to show",
                optional=True,
                default=256,
            ),
        ]

    def _generator(self):
        crash_layer = self._get_crash_layer(
            self.context, self.config.get("primary", None)
        )
        if crash_layer is None:
            vollog.error("This plugin requires a Windows mini kernel crash dump")
            raise ValueError("This plugin requires a Windows mini kernel crash dump")

        seen: Set[Tuple[int, int]] = set()
        emitted = 0
        limit = self.config.get("limit", 256)

        for (
            source,
            target,
            module_base,
            path,
            displacement,
        ) in crash_layer.iter_mini_kernel_module_references(self.config.get("name")):
            dedupe_key = (source, target)
            if dedupe_key in seen:
                continue
            seen.add(dedupe_key)

            yield (
                0,
                (
                    format_hints.Hex(source),
                    format_hints.Hex(target),
                    crash_layer.mini_kernel_module_name(path),
                    format_hints.Hex(module_base),
                    format_hints.Hex(displacement),
                    path,
                ),
            )

            emitted += 1
            if limit and emitted >= limit:
                break

    def run(self):
        return renderers.TreeGrid(
            [
                ("Source", format_hints.Hex),
                ("Target", format_hints.Hex),
                ("Module", str),
                ("ModuleBase", format_hints.Hex),
                ("Displacement", format_hints.Hex),
                ("Path", str),
            ],
            self._generator(),
        )
