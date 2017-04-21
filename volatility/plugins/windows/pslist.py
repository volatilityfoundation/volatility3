import volatility.framework.interfaces.plugins as plugins
from volatility.framework.configuration import requirements
from volatility.framework.renderers import TreeGrid


class PsList(plugins.PluginInterface):
    """Lists the processes present in a particular memory image"""

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
        kvo = self.config['primary.kernel_virtual_offset']
        ntkrnlmp = self.context.module("ntkrnlmp", layer_name = layer_name, offset = kvo)

        ps_aph_offset = ntkrnlmp.get_symbol("PsActiveProcessHead").address
        list_entry = ntkrnlmp.object(type_name = "_LIST_ENTRY", offset = kvo + ps_aph_offset)
        reloff = self.context.symbol_space.get_type("ntkrnlmp!_EPROCESS").relative_child_offset("ActiveProcessLinks")
        eproc = ntkrnlmp.object(type_name = "_EPROCESS", offset = list_entry.vol.offset - reloff)

        for proc in eproc.ActiveProcessLinks:
            yield proc

    def run(self):
        return TreeGrid([("PID", int),
                         ("PPID", int),
                         ("ImageFileName", str)],
                        self._generator())
