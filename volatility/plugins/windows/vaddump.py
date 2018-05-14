import logging

import volatility.framework.interfaces.plugins as interfaces_plugins
import volatility.plugins.windows.pslist as pslist
import volatility.plugins.windows.vadinfo as vadinfo
from volatility.framework import renderers
from volatility.framework.objects import utility

vollog = logging.getLogger()


class VadDump(interfaces_plugins.PluginInterface):
    """Dumps process memory ranges"""

    @classmethod
    def get_requirements(cls):
        # Since we're calling the plugin, make sure we have the plugin's requirements
        return vadinfo.VadInfo.get_requirements()

    def _generator(self, procs):

        plugin = vadinfo.VadInfo(self.context, self.config_path)
        chunk_size = 1024 * 1024 * 10

        for proc in procs:
            process_name = utility.array_to_string(proc.ImageFileName)

            # TODO: what kind of exceptions could this raise and what should we do?
            proc_layer_name = proc.add_process_layer()
            proc_layer = self.context.memory[proc_layer_name]

            for vad in plugin.list_vads(proc):
                try:
                    filedata = interfaces_plugins.FileInterface(
                        "pid.{0}.vad.{1:#x}-{2:#x}.dmp".format(proc.UniqueProcessId,
                                                               vad.get_start(),
                                                               vad.get_end()))

                    offset = vad.get_start()
                    out_of_range = vad.get_start() + vad.get_end()
                    while offset < out_of_range:
                        to_read = min(chunk_size, out_of_range - offset)
                        data = proc_layer.read(offset, to_read, pad = True)
                        if not data:
                            break
                        filedata.data.write(data)
                        offset += to_read

                    self.produce_file(filedata)
                    result_text = "Stored {}".format(filedata.preferred_filename)
                except Exception:
                    result_text = "Unable to dump {0:#x} - {1:#x}".format(vad.get_start(), vad.get_end())

                yield (0, (proc.UniqueProcessId,
                           process_name,
                           result_text))

    def run(self):
        plugin = pslist.PsList(self.context, self.config_path)

        return renderers.TreeGrid([("PID", int),
                                   ("Process", str),
                                   ("Result", str)],
                                  self._generator(plugin.list_processes()))
