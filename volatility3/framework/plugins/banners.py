# This file is Copyright 2020 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
import logging
from typing import List

from volatility3.framework import interfaces, renderers, layers
from volatility3.framework.configuration import requirements
from volatility3.framework.layers import scanners
from volatility3.framework.renderers import format_hints

vollog = logging.getLogger(__name__)


class Banners(interfaces.plugins.PluginInterface):
    """Attempts to identify potential linux banners in an image"""

    _required_framework_version = (2, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.TranslationLayerRequirement(
                name="primary", description="Memory layer to scan"
            )
        ]

    def _generator(self):
        layer = self.context.layers[self.config["primary"]]
        if isinstance(layer, layers.intel.Intel):
            layer = self.context.layers[layer.config["memory_layer"]]
        for offset, banner in self.locate_banners(self.context, layer.name):
            yield 0, (offset, banner)

    @classmethod
    def locate_banners(
        cls, context: interfaces.context.ContextInterface, layer_name: str
    ):
        """Identifies banners from a memory image"""
        layer = context.layers[layer_name]
        for offset in layer.scan(
            context=context,
            scanner=scanners.RegExScanner(
                rb"((Linux version|Darwin Kernel Version) [0-9]+\.[0-9]+\.[0-9]+|FreeBSD [0-9]+\.[0-9]+)"
            ),
        ):
            data = layer.read(offset, 0xFFF)
            data_index = data.find(b"\x00")
            if data_index > 0:
                data = data[:data_index].strip()
                failed = [
                    char
                    for char in data
                    if char
                    not in b" #()+,;/-.0123456789:@ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghijklmnopqrstuvwxyz~"
                ]
                if not failed:
                    yield format_hints.Hex(offset), str(
                        data, encoding="latin-1", errors="?"
                    )

    def run(self):
        return renderers.TreeGrid(
            [("Offset", format_hints.Hex), ("Banner", str)], self._generator()
        )
