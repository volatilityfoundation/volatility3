# This file is Copyright 2022 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

import logging
from typing import Iterator, List, Tuple

from volatility3.framework import exceptions, interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.objects import utility
from volatility3.framework.renderers import format_hints
from volatility3.plugins.windows import modules, pslist, vadinfo

vollog = logging.getLogger(__name__)


class VadTree(interfaces.plugins.PluginInterface):
    """Walk the VAD tree and display in tree format"""

    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(name = 'kernel', description = 'Windows kernel',
                                                     architectures = ["Intel32", "Intel64"]),
            requirements.PluginRequirement(name = 'modules', plugin = modules.Modules, version = (1, 1, 0)),
            requirements.PluginRequirement(name = 'pslist', plugin = pslist.PsList, version = (2, 0, 0)),
            requirements.PluginRequirement(name = 'vadinfo', plugin = vadinfo.VadInfo, version = (2, 0, 0)),
            requirements.ListRequirement(name = 'pid',
                                         element_type = int,
                                         description = "Process IDs to include (all other processes are excluded)",
                                         optional = True)
        ]

    @classmethod
    def get_heaps(cls, proc) -> List[int]:
        """
        """
        try:
            return [proc.get_peb().ProcessHeaps.dereference()]
        except exceptions.InvalidAddressException:
            #vollog.log()
            return []

    @classmethod
    def get_modules(cls, proc) -> List[int]:
        """
        """
        modules = []
        for mod in proc.load_order_modules():
            try:
                modules.append(mod.DllBase)
            except exceptions.InvalidAddressException:
                #vollog.log()
                continue
        return modules

    def get_stacks(self, proc: interfaces.objects.ObjectInterface) -> List[int]:
        #TODO Exception Processing
        stacks = []

        kernel = self.context.modules[self.config['kernel']]
        layer_name = kernel.layer_name

        kvo = self.context.layers[layer_name].config['kernel_virtual_offset']
        ntkrnlmp = self.context.module(kernel.symbol_table_name, layer_name=kernel.layer_name, offset=kvo)
        tleoffset = ntkrnlmp.get_type("_ETHREAD").relative_child_offset("ThreadListEntry")

        ethread = ntkrnlmp.object(object_type="_ETHREAD",
                                    offset=proc.ThreadListHead.Flink - tleoffset,
                                    absolute=True)

        while(True):
            stacks.append(ethread.Tcb.StackBase)
            ethread = ntkrnlmp.object(object_type="_ETHREAD",
                                        offset=ethread.ThreadListEntry.Flink - tleoffset,
                                        absolute=True)
            
            if(ethread.ThreadListEntry.Flink == proc.ThreadListHead.Blink):
                break

        return stacks
    
    def get_type(self, proc, vad) -> str:
        heaps = self.get_heaps(proc)
        modules = self.get_modules(proc)
        stacks = self.get_stacks(proc)
        
        type = renderers.NotApplicableValue()
        
        if(vad):
            if vad.get_start() in heaps:
                type = "Heap"
            elif vad.get_start() in modules:
                type = "Module"
            elif vad.get_start() in stacks:
                type = "Stack"
            else:
                try:
                    if vad.FileObject.FileName:
                        type = "File"
                except AttributeError:
                    pass
        
        return type

    def _generator(self, procs) -> Iterator[Tuple]: 
        for proc in procs:            
            levels = {}

            for vad in vadinfo.VadInfo.list_vads(proc):
                level = levels.get(vad.get_parent() & self.context.layers[vad.vol.layer_name].address_mask, -1) + 1
                levels[vad.vol.offset] = level

                type = self.get_type(proc, vad)

                yield(level, (proc.UniqueProcessId,
                            utility.array_to_string(proc.ImageFileName),
                            format_hints.Hex(vad.vol.offset),
                            type,
                            format_hints.Hex(vad.get_start()),
                            format_hints.Hex(vad.get_end()),
                            vad.get_tag()))

    def run(self) -> renderers.TreeGrid:
        kernel = self.context.modules[self.config['kernel']]
        filter_func = pslist.PsList.create_pid_filter(self.config.get('pid', None))

        return renderers.TreeGrid([('PID', int),
                                    ('Process', str),
                                    ('Offset', format_hints.Hex),
                                    ("Type", str),
                                    ('Start', format_hints.Hex),
                                    ('End', format_hints.Hex),
                                    ('Tag', str)],
                                    self._generator(
                                        pslist.PsList.list_processes(
                                            context = self.context,
                                            layer_name = kernel.layer_name,
                                            symbol_table = kernel.symbol_table_name,
                                            filter_func = filter_func)))
