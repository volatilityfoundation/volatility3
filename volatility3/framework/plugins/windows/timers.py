# This file is Copyright 2022 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

import logging

from typing import Iterator, List, Tuple

from volatility3.framework import layers, renderers, interfaces
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
    
    @classmethod
    def get_kernel_module(cls, context: interfaces.context.ContextInterface, layer_name: str, symbol_table: str):
        """Returns the kernel module based on the layer and symbol_table"""
        virtual_layer = context.layers[layer_name]
        if not isinstance(virtual_layer, layers.intel.Intel):
            raise TypeError("Virtual Layer is not an intel layer")

        kvo = virtual_layer.config["kernel_virtual_offset"]

        ntkrnlmp = context.module(symbol_table, layer_name = layer_name, offset = kvo)
        return ntkrnlmp
    
    @classmethod
    def get_kpcr(cls, context: interfaces.context.ContextInterface, layer_name: str, symbol_table: str) -> \
        interfaces.objects.ObjectInterface:
        """Returns the KPCR structure for a kernel"""
        
        ntkrnlmp = cls.get_kernel_module(context, layer_name, symbol_table)
        
        kprcb_offset = ntkrnlmp.get_symbol("KiProcessorBlock").address
        kprcb_object = ntkrnlmp.object("_KPRCB", offset = kprcb_offset, layer_name = layer_name)
        return kprcb_object

    def _generator(self) -> Iterator[Tuple]:

        kernel = self.context.modules[self.config['kernel']]
        layer_name = kernel.layer_name
        symbol_table = kernel.symbol_table_name

        kpcr = self.get_kpcr(self.context, layer_name, symbol_table)
        yield(0, ("KPCR Major/Minor", kpcr.CpuID.cast("string")))

    
    def run(self)-> renderers.TreeGrid:
        return renderers.TreeGrid([
            ("Variable", str), ("Value", str)
        ], self._generator())
