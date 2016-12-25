import volatility.framework.interfaces.plugins as plugins
from volatility.framework.configuration import requirements
from volatility.framework.renderers import TreeGrid


class PsList(plugins.PluginInterface):
    @classmethod
    def get_requirements(cls):
        return [requirements.TranslationLayerRequirement(name = 'primary',
                                                         description = 'Kernel Address Space'),
                requirements.SymbolRequirement(name = "ntkrnlmp",
                                               description = "Windows OS"),
                requirements.IntRequirement(name = 'pid',
                                            description = "Process ID",
                                            optional = True)]

    def update_configuration(self):
        """No operation since all values provided by config/requirements initially"""

    def _generator(self, eproc):
        for proc in eproc.ActiveProcessLinks:
            yield (0, (proc.UniqueProcessId, proc.InheritedFromUniqueProcessId,
                       proc.ImageFileName.cast("string", max_length = proc.ImageFileName.vol.count,
                                               errors = 'replace')))

    def run(self):
        virtual = self.config['primary']

        object_factory = self.context.object_factory("ntkrnlmp")

        kvo = self.config['primary.kernel_virtual_offset']
        ps_aph_offset = kvo + self.context.symbol_space.get_symbol("ntkrnlmp!PsActiveProcessHead").address
        list_entry = object_factory("_LIST_ENTRY", layer_name = virtual, offset = ps_aph_offset)
        reloff = self.context.symbol_space.get_type("ntkrnlmp!_EPROCESS").relative_child_offset("ActiveProcessLinks")
        eproc = object_factory("_EPROCESS", layer_name = virtual, offset = list_entry.vol.offset - reloff)

        return TreeGrid([("PID", int),
                         ("PPID", int),
                         ("ImageFileName", str)],
                        self._generator(eproc))
