import inspect

from volatility.framework.configuration import requirements
from volatility.framework.interfaces import plugins
from volatility.plugins import volshell


class Volshell(plugins.PluginInterface):
    """Shell environment to directly interact with a windows memory image"""

    @classmethod
    def get_requirements(cls):
        return (volshell.Volshell.get_requirements() +
                [requirements.SymbolRequirement(name = "nt_symbols", description = "Windows OS"),
                 requirements.IntRequirement(name = 'pid',
                                             description = "Process ID",
                                             optional = True)])

    def list_processes(self):
        """Lists all the processes in the primary layer"""

        # We only use the object factory to demonstrate how to use one
        layer_name = self.config['primary']
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
        # Note: "nt!_EPROCESS" could have been used, but would rely on the "nt" symbol table not already
        # having been present.  Strictly, the value of the requirement should be joined with the BANG character
        # defined in the constants file
        reloff = ntkrnlmp.get_type("_EPROCESS").relative_child_offset("ActiveProcessLinks")
        eproc = ntkrnlmp.object(type_name = "_EPROCESS", offset = list_entry.vol.offset - reloff)

        for proc in eproc.ActiveProcessLinks:
            yield proc

    def run(self):
        # Determine locals
        curframe = inspect.currentframe()

        # Provide some OS-agnostic convenience elements for ease
        layer_name = self.config['primary']
        kvo = self.context.memory[layer_name].config['kernel_virtual_offset']
        nt = self.context.module(self.config['nt_symbols'], layer_name = layer_name, offset = kvo)

        ps = lambda: list(self.list_processes())

        pid = self.config.get('pid', None)
        eproc = None
        if pid:
            for _x in ps():
                if _x.UniqueProcessId == pid:
                    eproc = _x
                    break

        return volshell.Volshell(self.context, "plugins.Volshell").run(curframe.f_locals)
