import volatility.framework.interfaces.plugins as plugins
from volatility.framework.configuration import requirements
from volatility.framework.renderers import TreeGrid
from volatility.framework.utility import adapters


class PsList(plugins.PluginInterface):
    @classmethod
    def get_requirements(cls):
        return [requirements.TranslationLayerRequirement(name = 'primary',
                                                         description = 'Kernel Address Space',
                                                         architectures = ["Intel32", "Intel64"]),
                requirements.SymbolRequirement(name = "ntkrnlmp",
                                               description = "Windows OS"),
                requirements.IntRequirement(name = 'pid',
                                            description = "Process ID",
                                            optional = True)]

    def update_configuration(self):
        """No operation since all values provided by config/requirements initially"""

    def _generator(self):
        for proc in self.list_processes():
            yield (0, (proc.UniqueProcessId, proc.InheritedFromUniqueProcessId,
                       proc.ImageFileName.cast("string", max_length = proc.ImageFileName.vol.count,
                                               errors = 'replace')))

    def list_processes(self):
        """Lists all the processes in the primary layer"""

        layer_name = self.config['primary']

        # We only use the object factory to demonstrate how to use one
        object_factory = adapters.object_factory(self.context, "ntkrnlmp")

        kvo = self.config['primary.kernel_virtual_offset']
        ps_aph_offset = kvo + self.context.symbol_space.get_symbol("ntkrnlmp!PsActiveProcessHead").address
        list_entry = object_factory("_LIST_ENTRY", layer_name = layer_name, offset = ps_aph_offset)
        reloff = self.context.symbol_space.get_type("ntkrnlmp!_EPROCESS").relative_child_offset("ActiveProcessLinks")
        eproc = object_factory("_EPROCESS", layer_name = layer_name, offset = list_entry.vol.offset - reloff)

        for proc in eproc.ActiveProcessLinks:
            yield proc

    def run(self):
        return TreeGrid([("PID", int),
                         ("PPID", int),
                         ("ImageFileName", str)],
                        self._generator())
