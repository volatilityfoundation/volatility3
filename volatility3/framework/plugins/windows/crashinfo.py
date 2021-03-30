# This file is Copyright 2021 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

import logging
import datetime
from volatility3.framework import interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.renderers import format_hints, conversion
from volatility3.framework.objects import utility

vollog = logging.getLogger(__name__)

class Crashinfo(interfaces.plugins.PluginInterface):
    _required_framework_version = (1, 0, 0)

    @classmethod
    def get_requirements(cls):
        return [
            requirements.TranslationLayerRequirement(name = 'primary',
                                                     description = 'Memory layer for the kernel',
                                                     architectures = ["Intel32", "Intel64"]), 
            ]
        
    def _generator(self, layer):
        header = layer.get_header()
        uptime = datetime.timedelta(microseconds=int(header.SystemUpTime) / 10)

        yield(0, (utility.array_to_string(header.Signature),
                  header.MajorVersion,
                  header.MinorVersion,
                  format_hints.Hex(header.DirectoryTableBase),
                  format_hints.Hex(header.PfnDataBase),
                  format_hints.Hex(header.PsLoadedModuleList),
                  format_hints.Hex(header.PsActiveProcessHead),
                  header.MachineImageType,
                  header.NumberProcessors,
                  format_hints.Hex(header.KdDebuggerDataBlock),
                  header.DumpType,
                  str(uptime),
                  utility.array_to_string(header.Comment),
                  conversion.wintime_to_datetime(header.SystemTime),
                  ))

    def run(self):
        layer = self._context.layers[self.config['primary.memory_layer']]
        return renderers.TreeGrid([("Signature", str),
                                   ("MajorVersion", int),
                                   ("MinorVersion", int),
                                   ("DirectoryTableBase", format_hints.Hex),
                                   ("PfnDataBase", format_hints.Hex),
                                   ("PsLoadedModuleList", format_hints.Hex),
                                   ("PsActiveProcessHead", format_hints.Hex),
                                   ("MachineImageType", int),
                                   ("NumberProcessors", int),
                                   ("KdDebuggerDataBlock", format_hints.Hex),
                                   ("DumpType", int),
                                   ("SystemUpTime", str),
                                   ("Comment", str),
                                   ("SystemTime", datetime.datetime),
                                   ], self._generator(layer))