# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
import logging
from typing import List

from volatility.framework import exceptions, renderers, interfaces
from volatility.framework.configuration import requirements
from volatility.framework.renderers import format_hints
from volatility.plugins.windows import pslist

vollog = logging.getLogger(__name__)


class Memdump(interfaces.plugins.PluginInterface):
    """Dump the addressable memory for a process"""

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        # Since we're calling the plugin, make sure we have the plugin's requirements
        return [
            requirements.TranslationLayerRequirement(name = 'primary',
                                                     description = 'Memory layer for the kernel',
                                                     architectures = ["Intel32", "Intel64"]),
            requirements.SymbolTableRequirement(name = "nt_symbols", description = "Windows kernel symbols"),
            requirements.PluginRequirement(name = 'pslist', plugin = pslist.PsList, version = (1, 0, 0)),
            requirements.IntRequirement(name = 'pid',
                                        description = "Process ID to include (all other processes are excluded)",
                                        optional = True)
        ]

    def _generator(self, procs):
        for proc in procs:
            data = b""
            process_name = proc.ImageFileName.cast("string",
                                                   max_length = proc.ImageFileName.vol.count,
                                                   errors = 'replace')
            pid = "Unknown"
            try:
                pid = proc.UniqueProcessId
                offset = format_hints.Hex(proc.vol.offset)
                filename = str(pid) + "." + str(offset)
                proc_layer_name = proc.add_process_layer()
                proc_layer = self.context.layers[proc_layer_name]
            except exceptions.InvalidAddressException as excp:
                vollog.debug(
                    "Process {}: invalid address {} in layer {}".format(pid, excp.invalid_address, excp.layer_name))
                continue

            # Create file for writing
            filedata = interfaces.plugins.FileInterface("{}.dmp".format(filename))

            for mapval in proc_layer.mapping(0x0, proc_layer.maximum_address, ignore_errors = True):
                offset, size, mapped_offset, _, maplayer = mapval
                data = proc_layer.read(offset, size, pad = True)
                try:
                    filedata.data.write(data)
                except exceptions.InvalidAddressException:
                    vollog.debug("Unable to write {}'s address {} [ {} ]to {}.dmp".format(process_name, offset,
                                                                                          proc.UniqueProcessId,
                                                                                          proc.UniqueProcessId))
                    continue

            try:
                result_text = "Writing {} [ {} ] to {}.dmp".format(process_name, proc.UniqueProcessId, filename)
                self.produce_file(filedata)
            except exceptions.InvalidAddressException:
                result_text = "Unable to write {} [ {} ]to {}.dmp".format(process_name, proc.UniqueProcessId, filename)

            yield (0, (result_text,))

    def run(self):
        filter_func = pslist.PsList.create_pid_filter([self.config.get('pid', None)])
        return renderers.TreeGrid([("Creating the following files:", str)],
                                  self._generator(
                                      pslist.PsList.list_processes(context = self.context,
                                                                   layer_name = self.config['primary'],
                                                                   symbol_table = self.config['nt_symbols'],
                                                                   filter_func = filter_func)))
