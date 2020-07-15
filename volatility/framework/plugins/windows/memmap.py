# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

from typing import List

from volatility.framework import exceptions, renderers, interfaces
from volatility.framework.configuration import requirements
from volatility.framework.renderers import format_hints
from volatility.plugins.windows import pslist, dlllist, ssdt, vadinfo


class Memmap(interfaces.plugins.PluginInterface):
    """Prints the memory map"""

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        # Since we're calling the plugin, make sure we have the plugin's requirements
        return [
            requirements.TranslationLayerRequirement(name = 'primary',
                                                     description = 'Memory layer for the kernel',
                                                     architectures = ["Intel32", "Intel64"]),
            requirements.SymbolTableRequirement(name = "nt_symbols", description = "Windows kernel symbols"),
            requirements.PluginRequirement(name = 'pslist', plugin = pslist.PsList, version = (1, 0, 0)),
            requirements.PluginRequirement(name = 'vadinfo', plugin = vadinfo.VadInfo, version = (1, 0, 0)),
            requirements.IntRequirement(name = 'pid',
                                        description = "Process ID to include (all other processes are excluded)",
                                        optional = True)
        ]

    def _generator(self, procs):

        for proc in procs:
            reverse_map = dict()
            offset = 0
            pid = "Unknown"

            try:
                pid = proc.UniqueProcessId
                proc_layer_name = proc.add_process_layer()
                proc_layer = self.context.layers[proc_layer_name]
            except exceptions.InvalidAddressException as excp:
                vollog.debug("Process {}: invalid address {} in layer {}".format(
                        pid, excp.invalid_address, excp.layer_name))
                continue

            for mapval in proc_layer.mapping(0x0, proc_layer.maximum_address, ignore_errors = True):
                kpage, _, vpage, page_size, maplayer = mapval
                cur_set = reverse_map.get(kpage >> 12, set())
                cur_set.add(("kernel", vpage))
                reverse_map[kpage >> 12] = cur_set
                yield(0, (proc.ImageFileName.cast("string", max_length = proc.ImageFileName.vol.count),
                    proc.UniqueProcessId,
                    format_hints.Hex(kpage), 
                    format_hints.Hex(vpage), 
                    format_hints.Hex(page_size), 
                    format_hints.Hex(offset)))
                offset += page_size


    def run(self):
        filter_func = pslist.PsList.create_pid_filter([self.config.get('pid', None)])

        return renderers.TreeGrid([ ("Process", str), ("PID", int),("Virtual", format_hints.Hex),("Physical", format_hints.Hex), ("Size", format_hints.Hex), ("Offset", format_hints.Hex)],
                                  self._generator(
                                      pslist.PsList.list_processes(context = self.context,
                                                                   layer_name = self.config['primary'],
                                                                   symbol_table = self.config['nt_symbols'],
                                                                   filter_func = filter_func)))