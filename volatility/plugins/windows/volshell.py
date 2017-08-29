import code
import inspect

from volatility.framework import renderers
from volatility.framework.configuration import requirements
from volatility.framework.interfaces import plugins


class Volshell(plugins.PluginInterface):
    """Lists the processes present in a particular memory image"""

    @classmethod
    def get_requirements(cls):
        return [requirements.TranslationLayerRequirement(name = 'primary',
                                                         description = 'Kernel Address Space',
                                                         architectures = ["Intel32", "Intel64"]),
                requirements.SymbolRequirement(name = "nt", description = "Windows OS"),
                requirements.IntRequirement(name = 'pid',
                                            description = "Process ID",
                                            optional = True)]

    def update_configuration(self):
        """No operation since all values provided by config/requirements initially"""

    def list_processes(self):
        """Lists all the processes in the primary layer"""

        # We only use the object factory to demonstrate how to use one
        kvo = self.config['primary.kernel_virtual_offset']
        ntkrnlmp = self.context.module(self.config['nt'], layer_name = self.config['primary'], offset = kvo)

        ps_aph_offset = ntkrnlmp.get_symbol("PsActiveProcessHead").address
        list_entry = ntkrnlmp.object(type_name = "_LIST_ENTRY", offset = kvo + ps_aph_offset)

        # This is example code to demonstrate how to use symbol_space directly, rather than through a module:
        #
        # ```
        # reloff = self.context.symbol_space.get_type(
        #          self.config['nt'] + constants.BANG + "_EPROCESS").relative_child_offset(
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

        # Provide some OS-agnostic convenience elements for ease
        context = self.context
        config = self.config
        layer_name = self.config['primary']
        kvo = config['primary.kernel_virtual_offset']
        nt = context.module(config['nt'], layer_name = layer_name, offset = kvo)

        ps = lambda: list(self.list_processes())
        members = lambda x: list(sorted(x.vol.members.keys()))

        pid = self.config.get('pid', None)
        eproc = None
        if pid:
            eproc = [x for x in ps() if x.UniqueProcessId == pid]

        # Determine locals
        curframe = inspect.currentframe()
        vars = curframe.f_globals.copy()
        vars.update(curframe.f_locals)

        # Try to enable tab completion
        try:
            import readline
        except ImportError:
            pass
        else:
            import rlcompleter
            completer = rlcompleter.Completer(namespace = vars)
            readline.set_completer(completer.complete)
            readline.parse_and_bind("tab: complete")
            print("Readline imported successfully")

        # TODO: provide help, consider generic functions (pslist?) and/or providing windows/linux functions

        code.interact(local = vars)

        return renderers.TreeGrid([], lambda: [])
