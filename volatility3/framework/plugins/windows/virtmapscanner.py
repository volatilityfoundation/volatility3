# This file is Copyright 2024 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

import logging
import functools
import json
import lzma

from typing import Iterable, Type, Tuple
from volatility3.framework import renderers, interfaces
from volatility3.framework.configuration import requirements
from volatility3.framework.layers.scanners import BytesScanner


vollog = logging.getLogger(__name__)


class VirtMapScanner(interfaces.plugins.PluginInterface):
    """Scans the entire kernel virtual memory space, and dumps its content to the disk. Allows to speed-up mapping operations afterwards, by specifying the output file as an argument to --virtmap-cache-path."""

    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 0)

    @classmethod
    def get_requirements(cls):
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Windows kernel",
                architectures=["Intel32", "Intel64"],
            ),
        ]

    @classmethod
    def virtmap_cache_file_producer(
        cls,
        sections: Iterable[Tuple[int, int]],
        layer: interfaces.layers.DataLayerInterface,
        open_method: Type[interfaces.plugins.FileHandlerInterface],
    ):
        results = {}
        for section in sections:
            scan_iterator = functools.partial(
                layer._scan_iterator, BytesScanner(""), [section]
            )
            scan_values = list(scan_iterator())
            results[str(section)] = scan_values

        results = {layer.config["class"]: results}

        # Prefer a simpler filename for convenience when passing as an argument
        # Leave the task of distinguishing between multiple virtmapcache files to the user
        # formatted_sections = "_".join([f"{hex(s[0])}-{hex(s[0] + s[1])}" for s in sections])
        # filename = f"virtmapcache_{layer.name}_{formatted_sections}.json.xz"
        filename = "virtmapcache.json.xz"
        file_handle = open_method(filename)
        json_data = json.dumps(results).encode()
        xz_data = lzma.compress(json_data)
        file_handle.write(xz_data)
        file_handle.close()

        return file_handle.preferred_filename

    def _generator(self):
        kernel = self.context.modules[self.config["kernel"]]
        kernel_layer = self.context.layers[kernel.layer_name]
        sections = [
            (
                kernel_layer.minimum_address,
                kernel_layer.maximum_address - kernel_layer.minimum_address,
            )
        ]

        res = (
            0,
            (
                str(sections),
                self.virtmap_cache_file_producer(sections, kernel_layer, self.open),
            ),
        )
        yield res

    def run(self):
        return renderers.TreeGrid(
            [
                ("Sections", str),
                ("Virtual mappings cache file output", str),
            ],
            self._generator(),
        )
