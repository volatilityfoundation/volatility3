# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

from typing import List

from volatility.framework import exceptions, renderers, interfaces
from volatility.framework.configuration import requirements
from volatility.framework.renderers import format_hints
from volatility.framework.objects import utility
from volatility.plugins.windows import pslist, dlllist, ssdt, vadinfo


class Memdump(interfaces.plugins.PluginInterface):
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
        
    @classmethod
    def mem_dump(cls, context: interfaces.context.ContextInterface, layer_name: str,
                 vad: interfaces.objects.ObjectInterface) -> bytes:
        """ Get data for each VA"""
        temp = b""

        proc_layer = context.layers[layer_name]
        chunk_size = 1024 * 1024 * 10
        offset = vad.get_start()
        out_of_range = vad.get_end()

        while offset < out_of_range:
            to_read = min(chunk_size, out_of_range - offset)
            data = proc_layer.read(offset, to_read, pad = True)
            if not data:
                break
            temp += data
            offset += to_read

        return temp


    def _generator(self, procs):
        #print("reading")
        test = 0
        for proc in procs:
            process_name = proc.ImageFileName.cast("string",
                                                   max_length = proc.ImageFileName.vol.count,
                                                   errors = 'replace')
            offset = 0
            pid = "Unknown"
            try:
                pid = proc.UniqueProcessId
                proc_layer_name = proc.add_process_layer()
                proc_layer = self.context.layers[proc_layer_name]
            except exceptions.InvalidAddressException as excp:
                vollog.debug("Process {}: invalid address {} in layer {}".format(pid, excp.invalid_address, excp.layer_name))
                continue
            
            for mapval in proc_layer.mapping(0x0, proc_layer.maximum_address, ignore_errors = True):
                vadd, _, vpage, page_size, maplayer = mapval
                try:
                    filedata = interfaces.plugins.FileInterface("{}.img".format(proc.UniqueProcessId))
                    temp_data = data = proc_layer.read(vadd, page_size, pad = True)
                    filedata.data.write(temp_data)
                    #self.produce_file(filedata)

                    result_text = "Writing {} [ {} ] to {}.img".format(process_name, proc.UniqueProcessId, proc.UniqueProcessId)
                except exceptions.InvalidAddressException:
                    result_text = "Unable to write {} [ {} ]to {}.img".format(process_name, proc.UniqueProcessId, proc.UniqueProcessId)

                yield(0, (result_text,))
                offset += page_size
            self.produce_file(filedata)
            



    def run(self):
        filter_func = pslist.PsList.create_pid_filter([self.config.get('pid', None)])
        #print("here run")
        return renderers.TreeGrid([ ("Result", str)],
                                  self._generator(
                                      pslist.PsList.list_processes(context = self.context,
                                                                   layer_name = self.config['primary'],
                                                                   symbol_table = self.config['nt_symbols'],
                                                                   filter_func = filter_func)))