# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

import logging
import os
from typing import List, Optional, Type

from volatility.framework import renderers, interfaces, constants, exceptions
from volatility.framework.configuration import requirements
from volatility.framework.interfaces import plugins

vollog = logging.getLogger(__name__)


class LayerWriter(plugins.PluginInterface):
    """Runs the automagics and writes out the primary layer produced by the stacker."""

    default_output_name = "output.raw"
    default_block_size = 0x500000

    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.TranslationLayerRequirement(name = 'primary',
                                                     description = 'Memory layer for the kernel',
                                                     architectures = ["Intel32", "Intel64"]),
            requirements.StringRequirement(name = 'output',
                                           description = 'Filename to output the chosen layer',
                                           optional = True,
                                           default = cls.default_output_name),
            requirements.IntRequirement(name = 'block_size',
                                        description = "Size of blocks to copy over",
                                        default = cls.default_block_size,
                                        optional = True)
        ]

    @classmethod
    def write_layer(cls,
                    context: interfaces.context.ContextInterface,
                    layer_name: str,
                    preferred_name: str,
                    file_handler: Type[plugins.FileHandlerInterface],
                    chunk_size: Optional[int] = None,
                    progress_callback: Optional[constants.ProgressCallback] = None) -> Optional[
        plugins.FileHandlerInterface]:
        """Produces a filedata from the named layer in the provided context

        Args:
            context: the context from which to read the memory layer
            layer_name: the name of the layer to write out
            preferred_name: a string with the preferred filename for hte file
            chunk_size: an optional size for the chunks that should be written (defaults to 0x500000)
            progress_callback: an optional function that takes a percentage and a string that displays output
        """

        if layer_name not in context.layers:
            raise exceptions.LayerException("Layer not found")
        layer = context.layers[layer_name]

        if chunk_size is None:
            chunk_size = cls.default_block_size

        filehandler = file_handler(preferred_name)
        with filehandler as filedata:
            for i in range(0, layer.maximum_address, chunk_size):
                current_chunk_size = min(chunk_size, layer.maximum_address - i)
                data = layer.read(i, current_chunk_size, pad = True)
                filedata.write(data)
                if progress_callback:
                    progress_callback((i / layer.maximum_address) * 100, 'Writing layer {}'.format(layer_name))
        return filehandler

    def _generator(self):
        if self.config['primary'] not in self.context.layers:
            yield 0, ('Layer Name does not exist',)
        elif os.path.exists(self.config.get('output', self.default_output_name)):
            yield 0, ('Refusing to overwrite existing output file',)
        else:
            output_name = self.config.get('output', self.default_output_name)
            try:
                filedata = self.write_layer(self.context, self.config['primary'], output_name,
                                            self._file_handler,
                                            self.config.get('block_size', self.default_block_size),
                                            progress_callback = self._progress_callback)
                filedata.commit()
            except IOError as excp:
                yield 0, ('Layer cannot be written to {}: {}'.format(self.config['output_name'], excp),)

            yield 0, ('Layer has been written to {}'.format(output_name),)

    def run(self):
        return renderers.TreeGrid([("Status", str)], self._generator())
