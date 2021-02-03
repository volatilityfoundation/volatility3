  
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
        
    def _generator(self, segments):
        for seg in segments:
            yield(0,(seg[0],seg[1],seg[2]))

    def run(self):

        if self.config["primary.memory_layer.class"] == "volatility.framework.layers.crash.WindowsCrashDump32Layer":
            crashdump = crash.WindowsCrashDump32Layer(self.context, self.config_path, self.config['primary'])

        elif self.config["primary.memory_layer.class"] == "volatility.framework.layers.crash.WindowsCrashDump64Layer":
            crashdump = crash.WindowsCrashDump64Layer(self.context, self.config_path, self.config['primary'])
        
        else:
            vollog.log(constants.LOGLEVEL_VVVV, "Error: Windows crashdump file needed")
            return


        return renderers.TreeGrid([("StartAddress", int),("FileOffset", int),("Length", int)],self._generator(crashdump._segments))