import volatility.framework.interfaces.plugins as plugins
import volatility.plugins.windows.pslist as pslist
from volatility.framework.configuration import requirements
from volatility.framework import renderers
from volatility.framework.renderers import format_hints

class DllList(plugins.PluginInterface):
    @classmethod
    def get_requirements(cls):
        return [requirements.TranslationLayerRequirement(name = 'primary',
                                                         description = 'Kernel Address Space'),
                requirements.SymbolRequirement(name = "ntkrnlmp",
                                               description = "Windows OS"),
                requirements.IntRequirement(name = 'pid',
                                            description = "Process ID",
                                            optional = True)]

    def _generator(self, procs):

        for proc in procs:

            for entry in proc.load_order_modules(): 

                yield (0, (proc.UniqueProcessId, 
                       proc.ImageFileName.cast("string", max_length = proc.ImageFileName.vol.count,
                                               errors = 'replace'),
                       format_hints.Hex(entry.DllBase), format_hints.Hex(entry.SizeOfImage), 
                       entry.BaseDllName.String, entry.FullDllName.String))

    def run(self):

        plugin = pslist.PsList(self.context, "plugins.DllList")

        return renderers.TreeGrid([("PID", int),
                         ("Process", str),
                         ("Base", format_hints.Hex),
                         ("Size", format_hints.Hex),
                         ("Name", str), 
                         ("Path", str)],
                        self._generator(plugin.list_processes()))
