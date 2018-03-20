import os
import volatility.framework.interfaces.plugins as interfaces_plugins
import volatility.plugins.windows.vadinfo as vadinfo
import volatility.plugins.windows.pslist as pslist
from volatility.framework import renderers
from volatility.framework.objects import utility
from volatility.framework.configuration import requirements
import logging

vollog = logging.getLogger()

class VadDump(interfaces_plugins.PluginInterface):
    """Dumps process memory ranges"""

    @classmethod
    def get_requirements(cls):
        # Since we're calling the plugin, make sure we have the plugin's requirements
        return vadinfo.VadInfo.get_requirements() + [requirements.StringRequirement(name = "outdir",
                                               description = "Output directory",
                                               default = None,
                                               optional = False)]

    def _generator(self, procs):

        plugin = vadinfo.VadInfo(self.context, "plugins.VadDump")
        chunk_size = 1024 * 1024 * 10

        for proc in procs:
            process_name = utility.array_to_string(proc.ImageFileName)

            # TODO: what kind of exceptions could this raise and what should we do?
            proc_layer_name = proc.add_process_layer(self.context)
            proc_layer = self.context.memory[proc_layer_name]

            for vad in plugin.list_vads(proc):
                try:
                    file_name = os.path.join(self.config["outdir"],
                                             "pid.{0}.vad.{1:#x}-{2:#x}.dmp".format(proc.UniqueProcessId, vad.get_start(), vad.get_end()))

                    if os.path.exists(file_name):
                        raise FileExistsError

                    with open(file_name, "wb") as handle:
                        offset = vad.get_start()
                        out_of_range = vad.get_start() + vad.get_end()
                        while offset < out_of_range:
                            to_read = min(chunk_size, out_of_range - offset)
                            data = proc_layer.read(offset, to_read, pad = True)
                            if not data:
                                break
                            handle.write(data)
                            offset += to_read

                    result_text = "Saved to {}".format(os.path.basename(file_name))
                except FileExistsError:
                    result_text = "Refusing to overwrite the existing {}".format(file_name)
                except Exception:
                    result_text = "Unable to dump {0:#x} - {1:#x}".format(vad.get_start(), vad.get_end())

                yield (0, (proc.UniqueProcessId,
                           process_name,
                           result_text))

    def run(self):

        try:
            # the optional=False requirement should make sure this always exists
            os.makedirs(self.config["outdir"])
        except FileExistsError:
            pass
        except OSError:
            # is this what we want to raise here?
            raise OSError("Cannot create the desired output directory!")

        plugin = pslist.PsList(self.context, "plugins.VadDump")

        return renderers.TreeGrid([("PID", int),
                                   ("Process", str),
                                   ("Result", str)],
                                  self._generator(plugin.list_processes()))
