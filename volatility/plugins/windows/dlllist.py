import volatility.framework.interfaces.plugins as plugins
import volatility.plugins.windows.pslist as pslist
from volatility.framework.configuration import requirements
from volatility.framework.renderers import TreeGrid
from volatility.framework.renderers.format_hints import Hex

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
                       Hex(entry.DllBase), Hex(entry.SizeOfImage), 
                       entry.BaseDllName.String, entry.FullDllName.String))

    def run(self):

        plugin = pslist.PsList(self.context, "plugins.DllList")

        return TreeGrid([("PID", int),
                         ("Process", str),
                         ("Base", Hex),
                         ("Size", Hex),
                         ("Name", str), 
                         ("Path", str)],
                        self._generator(plugin.list_processes()))
