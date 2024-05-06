# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

import logging
from typing import List, Optional, Type

from volatility3.framework import renderers, interfaces, constants, exceptions
from volatility3.framework.configuration import requirements
from volatility3.framework.interfaces import plugins

vollog = logging.getLogger(__name__)


class LayerWriter(plugins.PluginInterface):
    """Runs the automagics and writes out the primary layer produced by the stacker."""

    default_block_size = 0x500000

    _required_framework_version = (2, 0, 0)
    _version = (2, 0, 1)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.TranslationLayerRequirement(
                name="primary", description="Memory layer for the kernel"
            ),
            requirements.IntRequirement(
                name="block_size",
                description="Size of blocks to copy over",
                default=cls.default_block_size,
                optional=True,
            ),
            requirements.BooleanRequirement(
                name="list",
                description="List available layers",
                default=False,
                optional=True,
            ),
            requirements.StringRequirement(
                name="output",
                description="Output filename",
                optional=True,
            ),
            requirements.ListRequirement(
                name="layers",
                element_type=str,
                description="Names of layers to write (defaults to the highest non-mapped layer)",
                default=None,
                optional=True,
            ),
        ]

    @classmethod
    def write_layer(
        cls,
        context: interfaces.context.ContextInterface,
        layer_name: str,
        preferred_name: str,
        open_method: Type[plugins.FileHandlerInterface],
        chunk_size: Optional[int] = None,
        progress_callback: Optional[constants.ProgressCallback] = None,
    ) -> Optional[plugins.FileHandlerInterface]:
        """Produces a FileHandler from the named layer in the provided context or None on failure

        Args:
            context: the context from which to read the memory layer
            layer_name: the name of the layer to write out
            preferred_name: a string with the preferred filename for hte file
            chunk_size: an optional size for the chunks that should be written (defaults to 0x500000)
            open_method: class for creating FileHandler context managers
            progress_callback: an optional function that takes a percentage and a string that displays output
        """

        if layer_name not in context.layers:
            raise exceptions.LayerException("Layer not found")
        layer = context.layers[layer_name]

        if chunk_size is None:
            chunk_size = cls.default_block_size

        file_handle = open_method(preferred_name)
        for i in range(0, layer.maximum_address, chunk_size):
            current_chunk_size = min(chunk_size, layer.maximum_address + 1 - i)
            data = layer.read(i, current_chunk_size, pad=True)
            file_handle.write(data)
            if progress_callback:
                progress_callback(
                    (i / layer.maximum_address) * 100, f"Writing layer {layer_name}"
                )
        return file_handle

    def _generator(self):
        if self.config["list"]:
            for name in self.context.layers:
                yield 0, (name,)
        else:
            # Choose the most recently added layer that isn't virtual
            if not self.config["layers"]:
                self.config["layers"] = []
                for name in self.context.layers:
                    if "mapped" not in self.context.layers[name].metadata:
                        self.config["layers"] = [name]

            for name in self.config["layers"]:
                # Check the layer exists and validate the output file
                if name not in self.context.layers:
                    yield 0, (f"Layer Name {name} does not exist",)
                else:
                    default_output_name = f"{name}.raw"
                    output_name = self.config.get("output", default_output_name)
                    try:
                        file_handle = self.write_layer(
                            self.context,
                            name,
                            output_name,
                            self.open,
                            self.config.get("block_size", self.default_block_size),
                            progress_callback=self._progress_callback,
                        )
                        file_handle.close()
                        output_name = file_handle._output_filename
                    except IOError as excp:
                        yield 0, (f"Layer cannot be written to {output_name}: {excp}",)

                    yield 0, (f"Layer has been written to {output_name}",)

    def _generate_layers(self):
        """List layer names from this run"""
        for name in self.context.layers:
            yield (0, (name, self.context.layers[name].__class__.__name__))

    def run(self):
        if self.config["list"]:
            return renderers.TreeGrid(
                [("Layer name", str), ("Layer type", str)], self._generate_layers()
            )
        return renderers.TreeGrid([("Status", str)], self._generator())
