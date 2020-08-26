# This file is Copyright 2020 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
import logging
from typing import List

from volatility.framework import exceptions, renderers, interfaces
from volatility.framework.configuration import requirements
from volatility.framework.renderers import format_hints
from volatility.plugins.windows import pslist

vollog = logging.getLogger(__name__)


class Memmap(interfaces.plugins.PluginInterface):
    """Prints the memory map"""

    _required_framework_version = (2, 0, 0)

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
                                        optional = True),
            requirements.BooleanRequirement(name = 'dump',
                                            description = "Extract listed memory segments",
                                            default = False,
                                            optional = True)
        ]

    def _generator(self, procs):
        for proc in procs:
            pid = "Unknown"

            try:
                pid = proc.UniqueProcessId
                proc_layer_name = proc.add_process_layer()
                proc_layer = self.context.layers[proc_layer_name]
            except exceptions.InvalidAddressException as excp:
                vollog.debug("Process {}: invalid address {} in layer {}".format(pid, excp.invalid_address,
                                                                                 excp.layer_name))
                continue

            filedata = interfaces.plugins.FileInterface("pid.{}.dmp".format(pid))

            for mapval in proc_layer.mapping(0x0, proc_layer.maximum_address, ignore_errors = True):
                offset, size, mapped_offset, mapped_size, maplayer = mapval

                dumped = False
                if self.config['dump']:
                    try:
                        data = proc_layer.read(offset, size, pad = True)
                        filedata.data.write(data)
                        dumped = True
                    except exceptions.InvalidAddressException:
                        vollog.debug("Unable to write {}'s address {} to {}.dmp".format(
                            proc_layer_name, offset, filedata.preferred_filename))

                yield (0, (format_hints.Hex(offset), format_hints.Hex(mapped_offset), format_hints.Hex(mapped_size),
                           format_hints.Hex(offset), dumped))
                offset += mapped_size

            self.produce_file(filedata)

    def run(self):
        filter_func = pslist.PsList.create_pid_filter([self.config.get('pid', None)])

        return renderers.TreeGrid([("Virtual", format_hints.Hex), ("Physical", format_hints.Hex),
                                   ("Size", format_hints.Hex), ("Offset", format_hints.Hex), ("Dumped", bool)],
                                  self._generator(
                                      pslist.PsList.list_processes(context = self.context,
                                                                   layer_name = self.config['primary'],
                                                                   symbol_table = self.config['nt_symbols'],
                                                                   filter_func = filter_func)))
