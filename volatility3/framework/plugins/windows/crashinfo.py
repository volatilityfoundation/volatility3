  
# This file is Copyright 2021 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

import logging
from volatility.framework import interfaces, renderers
from volatility.framework.configuration import requirements
from volatility.framework.layers import crash
from volatility.framework import exceptions

vollog = logging.getLogger(__name__)

class Crashinfo(interfaces.plugins.PluginInterface):
    _required_framework_version = (2, 0, 0)

    @classmethod
    def get_requirements(cls):
        return [
            requirements.TranslationLayerRequirement(name = 'primary',
                                                     description = 'Memory layer for the kernel',
                                                     architectures = ["Intel32", "Intel64"]), 
            ]
        
    def _generator(self, layer):
        for offset, length, mapped_offset in layer.mapping(0x0, layer.maximum_address, ignore_errors = True):
            yield(0,(offset,length,mapped_offset))

    def run(self):

        layer = self._context.layers[self.config['primary.memory_layer']]

        return renderers.TreeGrid([("StartAddress", int),("FileOffset", int),("Length", int)],self._generator(layer))