import volatility.framework.interfaces.plugins as plugins
from volatility.framework.configuration import requirements
from volatility.framework.renderers import TreeGrid


class PsList(plugins.PluginInterface):
    @classmethod
    def get_schema(cls):
        return [requirements.TranslationLayerRequirement(name = 'primary',
                                                         description = 'Kernel Address Space',
                                                         constraints = {"type": "memory",
                                                                        "architecture": ["ia32", "pae"]}),
                requirements.SymbolRequirement(name = "ntkrnlmp",
                                               description = "Windows OS",
                                               constraints = {"type": "symbols",
                                                              "os": "windows",
                                                              "architecture": ["ia32", "pae"]}),
                requirements.IntRequirement(name = 'pid',
                                            description = "Process ID",
                                            optional = True),
                requirements.IntRequirement(name = 'offset',
                                            description = 'Virtual address of any process')]

    @staticmethod
    def kernel_process_from_physical_process(ctx, physical_layer, kernel_layer, offset):
        """Return a kernel process object from physical process data."""
        # Get the process in the physical space
        flateproc = ctx.object("ntkrnlmp!_EPROCESS", physical_layer, offset = offset)
        # Determine the relative offset from the Thread head to the ThreadListEntry
        reloff = ctx.symbol_space.get_type("ntkrnlmp!_ETHREAD").relative_child_offset("ThreadListEntry")
        # Get the thread object in kernel space from the
        ethread = ctx.object("ntkrnlmp!_ETHREAD", kernel_layer, offset = flateproc.ThreadListHead.Flink - reloff)
        # Get the process from the thread object in kernel space
        return ethread.owning_process()

    def _generator(self, eproc):
        for proc in eproc.ActiveProcessLinks:
            yield (0, (proc.UniqueProcessId, proc.InheritedFromUniqueProcessId,
                       proc.ImageFileName.cast("String", max_length = proc.ImageFileName.vol.count,
                                               errors = 'replace')))

    def run(self):

        # Use the primary twice until we figure out how to specify base layers of a particular translation layer
        eproc = self.kernel_process_from_physical_process(self.context,
                                                          self.config['primary'],
                                                          self.config['primary'],
                                                          self.config['offset'])

        return TreeGrid([("PID", int),
                         ("PPID", int),
                         ("ImageFileName", str)],
                        self._generator(eproc))
