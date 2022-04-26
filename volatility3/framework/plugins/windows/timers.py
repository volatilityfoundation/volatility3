# This file is Copyright 2022 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

import logging

from typing import Iterator, List, Tuple

from volatility3.framework import constants, renderers, symbols, interfaces
from volatility3.framework.configuration import requirements

vollog = logging.getLogger(__name__)

class Timers(interfaces.plugins.PluginInterface):
    """Print kernel timers and associated module DPCs"""

    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 0)

    @classmethod
    def get_requirements(cls)-> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(name = 'kernel', description = 'Windows kernel',
                                           architectures = ["Intel32", "Intel64"])
        ]

    def _generator(self) -> Iterator[Tuple]:
        kernel = self.context.modules[self.config['kernel']]
        layer_name = kernel.layer_name

        kvo = self.context.layers[layer_name].config['kernel_virtual_offset']
        kernel_module = self.context.module(kernel.symbol_table_name, layer_name = layer_name, offset = kvo)
        
        kpb_offset = kernel_module.get_symbol("KiProcessorBlock").address
        
        # x86
        if not symbols.symbol_table_is_64bit(self.context, kernel.symbol_table_name):
            yield(0, [0, "TEST", 0, "TEST", 0, "TEST"])
        # x64
        else:
            kpcr_size = kernel_module.get_type("_KPCR").size
            pointer_size = self.context.modules[self.config['kernel']].get_type("pointer").size
            cal_offset = kpb_offset - (kpcr_size + pointer_size)
            print(kpb_offset, kpcr_size, cal_offset)

            kpcr = kernel_module.object(object_type = "_KPCR", offset = cal_offset)
            print(kpcr.MajorVersion)
            print(kpcr.MinorVersion)
            yield(0, [0, "TEST", 0, "TEST", 0, "TEST"])
    
    def run(self)-> renderers.TreeGrid:
        return renderers.TreeGrid([
            ("Offset", int),
            ("DueTime", str),
            ("Period(ms)", int),
            ("Signaled", str),
            ("Routine", int),
            ("Module", str)
        ], self._generator())
