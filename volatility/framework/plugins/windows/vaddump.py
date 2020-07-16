# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

import logging
from typing import List

from volatility.framework import renderers, interfaces, exceptions
from volatility.framework.configuration import requirements
from volatility.framework.objects import utility
from volatility.plugins.windows import pslist, vadinfo

vollog = logging.getLogger(__name__)


class VadDump(interfaces.plugins.PluginInterface):
    """Dumps process memory ranges."""
    _version = (1, 1, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        # Since we're calling the plugin, make sure we have the plugin's requirements
        return [requirements.TranslationLayerRequirement(name = 'primary',
                                                         description = 'Memory layer for the kernel',
                                                         architectures = ["Intel32", "Intel64"]),
                requirements.SymbolTableRequirement(name = "nt_symbols", description = "Windows kernel symbols"),
                # TODO: Convert this to a ListRequirement so that people can filter on sets of ranges
                requirements.IntRequirement(name = 'address',
                                            description = "Process virtual memory address to include " \
                                                          "(all other address ranges are excluded). This must be " \
                                                          "a base address, not an address within the desired range.",
                                            optional = True),
                requirements.ListRequirement(name = 'pid',
                                             element_type = int,
                                             description = "Process IDs to include (all other processes are excluded)",
                                             optional = True),
                requirements.PluginRequirement(name = 'pslist', plugin = pslist.PsList, version = (1, 0, 0)),
                requirements.PluginRequirement(name = 'vadinfo', plugin = vadinfo.VadInfo, version = (1, 0, 0)),
                ]

    @classmethod
    def vad_dump(cls, context: interfaces.context.ContextInterface, layer_name: str,
                 vad: interfaces.objects.ObjectInterface) -> bytes:
        """
            Returns VAD content
        """

        tmp_data = b""
        proc_layer = context.layers[layer_name]
        chunk_size = 1024 * 1024 * 10
        offset = vad.get_start()
        out_of_range = vad.get_end()
        # print("walking from {:x} to {:x} | {:x}".format(offset, out_of_range, out_of_range-offset))
        while offset < out_of_range:
            to_read = min(chunk_size, out_of_range - offset)
            data = proc_layer.read(offset, to_read, pad = True)
            if not data:
                break
            tmp_data += data
            offset += to_read

        return tmp_data

    def _generator(self, procs):

        filter_func = lambda _: False
        if self.config.get('address', None) is not None:
            filter_func = lambda x: x.get_start() not in [self.config['address']]

        for proc in procs:
            process_name = utility.array_to_string(proc.ImageFileName)

            proc_id = "Unknown"
            try:
                proc_id = proc.UniqueProcessId
                proc_layer_name = proc.add_process_layer()
            except exceptions.InvalidAddressException as excp:
                vollog.debug("Process {}: invalid address {} in layer {}".format(proc_id, excp.invalid_address,
                                                                                 excp.layer_name))
                continue

            for vad in vadinfo.VadInfo.list_vads(proc, filter_func = filter_func):
                try:
                    filedata = interfaces.plugins.FileInterface("pid.{0}.vad.{1:#x}-{2:#x}.dmp".format(
                        proc.UniqueProcessId, vad.get_start(), vad.get_end()))

                    data = self.vad_dump(self.context, proc_layer_name, vad)
                    filedata.data.write(data)

                    self.produce_file(filedata)
                    result_text = "Stored {}".format(filedata.preferred_filename)
                except exceptions.InvalidAddressException:
                    result_text = "Unable to dump {0:#x} - {1:#x}".format(vad.get_start(), vad.get_end())

                yield (0, (proc.UniqueProcessId, process_name, result_text))

    def run(self):
        filter_func = pslist.PsList.create_pid_filter(self.config.get('pid', None))

        return renderers.TreeGrid([("PID", int), ("Process", str), ("Result", str)],
                                  self._generator(
                                      pslist.PsList.list_processes(context = self.context,
                                                                   layer_name = self.config['primary'],
                                                                   symbol_table = self.config['nt_symbols'],
                                                                   filter_func = filter_func)))
