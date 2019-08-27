# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl_v1.0
#

import logging
import os
from typing import List

from volatility.framework import renderers, interfaces
from volatility.framework.configuration import requirements
from volatility.framework.interfaces import plugins

vollog = logging.getLogger(__name__)


class LayerWriter(plugins.PluginInterface):
    """Runs the automagics and lists out the generated layers if no layer name is specified, otherwise writes out the named layer"""

    default_output_name = "output.raw"
    default_block_size = 0x500000

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.TranslationLayerRequirement(
                name = 'primary', description = 'Memory layer for the kernel', architectures = ["Intel32", "Intel64"]),
            requirements.StringRequirement(
                name = 'layer_name', description = 'Name of the layer to write out', default = None, optional = True),
            requirements.StringRequirement(
                name = 'output',
                description = 'Filename to output the chosen layer',
                optional = True,
                default = cls.default_output_name),
            requirements.IntRequirement(
                name = 'block_size',
                description = "Size of blocks to copy over",
                default = cls.default_block_size,
                optional = True)
        ]

    def _generator(self):
        if self.config.get('layer_name', None) is None:
            for layer_name in self.context.layers:
                yield 0, ("Layer '{}' available as '{}'".format(layer_name,
                                                                self.context.layers[layer_name].__class__.__name__), )
        elif self.config['layer_name'] not in self.context.layers:
            yield 0, ('Layer Name does not exist', )
        elif os.path.exists(self.config.get('output', self.default_output_name)):
            yield 0, ('Refusing to overwrite existing output file', )
        else:
            chunk_size = self.config.get('block_size', self.default_block_size)
            layer = self.context.layers[self.config['layer_name']]

            try:
                filedata = plugins.FileInterface(self.config.get('output', self.default_output_name))
                for i in range(0, layer.maximum_address, chunk_size):
                    current_chunk_size = min(chunk_size, layer.maximum_address - i)
                    data = layer.read(i, current_chunk_size, pad = True)
                    filedata.data.write(data)
                self.produce_file(filedata)
            except Exception as excp:
                import pdb
                pdb.set_trace()
                vollog.warning("Unable to write out output file")

            yield 0, ('Layer {} has been written to {}'.format(self.config['layer_name'],
                                                               self.config.get('output', self.default_output_name)), )

    def run(self):
        return renderers.TreeGrid([("Status", str)], self._generator())
