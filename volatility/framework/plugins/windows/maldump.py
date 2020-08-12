# This file is Copyright 2020 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
import logging

from volatility.framework import interfaces, exceptions, renderers
from volatility.framework.configuration import requirements
from volatility.framework.objects import utility
from volatility.plugins.windows import vaddump, pslist, malfind

vollog = logging.getLogger(__name__)


class Maldump(interfaces.plugins.PluginInterface):
    """Lists process memory ranges that potentially contain injected code."""

    @classmethod
    def get_requirements(cls):
        # Since we're calling the plugin, make sure we have the plugin's requirements
        return [
            requirements.TranslationLayerRequirement(name = 'primary',
                                                     description = 'Memory layer for the kernel',
                                                     architectures = ["Intel32", "Intel64"]),
            requirements.SymbolTableRequirement(name = "nt_symbols", description = "Windows kernel symbols"),
            requirements.ListRequirement(name = 'pid',
                                         element_type = int,
                                         description = "Process IDs to include (all other processes are excluded)",
                                         optional = True),
            requirements.PluginRequirement(name = 'pslist', plugin = pslist.PsList, version = (1, 0, 0)),
            requirements.PluginRequirement(name = 'malfind', plugin = malfind.Malfind, version = (1, 0, 0)),
            requirements.PluginRequirement(name = 'vaddump', plugin = vaddump.VadDump, version = (1, 1, 0)),
        ]

    def _generator(self, procs):
        for proc in procs:
            process_name = utility.array_to_string(proc.ImageFileName)

            for vad, data in malfind.Malfind.list_injections(self.context, self.config["primary"],
                                                             self.config["nt_symbols"],
                                                             proc):

                try:
                    filedata = interfaces.plugins.FileInterface("malfind.pid.{0}.vad.{1:#x}-{2:#x}.dmp".format(
                        proc.UniqueProcessId, vad.get_start(), vad.get_end()))

                    data = vaddump.VadDump.vad_dump(self.context, self.config['primary'], vad)
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
