import volatility.framework.interfaces.plugins as plugins
from volatility.framework import renderers
from volatility.framework.configuration import requirements


class PsList(plugins.PluginInterface):
    """Lists the processes present in a particular windows memory image"""

    @classmethod
    def get_requirements(cls):
        return [requirements.TranslationLayerRequirement(name = 'primary',
                                                         description = 'Kernel Address Space',
                                                         architectures = ["Intel32", "Intel64"]),
                requirements.SymbolRequirement(name = "nt_symbols", description = "Windows OS"),
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
        kvo = self.context.memory[layer_name].config['kernel_virtual_offset']
        ntkrnlmp = self.context.module(self.config['nt_symbols'], layer_name = layer_name, offset = kvo)

        ps_aph_offset = ntkrnlmp.get_symbol("PsActiveProcessHead").address
        list_entry = ntkrnlmp.object(type_name = "_LIST_ENTRY", offset = kvo + ps_aph_offset)

        # This is example code to demonstrate how to use symbol_space directly, rather than through a module:
        #
        # ```
        # reloff = self.context.symbol_space.get_type(
        #          self.config['nt_symbols'] + constants.BANG + "_EPROCESS").relative_child_offset(
        #          "ActiveProcessLinks")
        # ```
        #
        # Note: "nt_symbols!_EPROCESS" could have been used, but would rely on the "nt_symbols" symbol table not already
        # having been present.  Strictly, the value of the requirement should be joined with the BANG character
        # defined in the constants file
        reloff = ntkrnlmp.get_type("_EPROCESS").relative_child_offset("ActiveProcessLinks")
        eproc = ntkrnlmp.object(type_name = "_EPROCESS", offset = list_entry.vol.offset - reloff)

        for proc in eproc.ActiveProcessLinks:
            yield proc

    def run(self):
        return renderers.TreeGrid([("PID", int),
                                   ("PPID", int),
                                   ("ImageFileName", str)],
                                  self._generator())
