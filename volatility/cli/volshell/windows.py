# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl_v1.0
#

import inspect
from typing import Callable, Dict

from volatility.cli.volshell import shellplugin
from volatility.framework.configuration import requirements


class Volshell(shellplugin.Volshell):
    """Shell environment to directly interact with a windows memory image."""

    @classmethod
    def get_requirements(cls):
        return (super().get_requirements() + [
            requirements.SymbolTableRequirement(name = "nt_symbols", description = "Windows kernel symbols"),
            requirements.IntRequirement(name = 'pid', description = "Process ID", optional = True)
        ])

    def list_processes(self):
        """Lists all the processes in the primary layer."""

        # We only use the object factory to demonstrate how to use one
        layer_name = self.config['primary']
        kvo = self.context.layers[layer_name].config['kernel_virtual_offset']
        ntkrnlmp = self.context.module(self.config['nt_symbols'], layer_name = layer_name, offset = kvo)

        ps_aph_offset = ntkrnlmp.get_symbol("PsActiveProcessHead").address
        list_entry = ntkrnlmp.object(object_type = "_LIST_ENTRY", offset = ps_aph_offset)

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
        eproc = ntkrnlmp.object(object_type = "_EPROCESS", offset = list_entry.vol.offset - reloff, absolute = True)

        for proc in eproc.ActiveProcessLinks:
            yield proc

    def load_functions(self) -> Dict[str, Callable]:
        result = super().load_functions()
        result.update({'ps': lambda: list(self.list_processes())})
        return result

    def run(self, additional_locals = None):
        # Determine locals
        curframe = inspect.currentframe()

        # Provide some OS-agnostic convenience elements for ease
        layer_name = self.config['primary']
        kvo = self.context.layers[layer_name].config['kernel_virtual_offset']
        nt = self.context.module(self.config['nt_symbols'], layer_name = layer_name, offset = kvo)
        ps = lambda: list(self.list_processes())

        pid = self.config.get('pid', None)
        eproc = None
        if pid:
            for _x in ps():
                if _x.UniqueProcessId == pid:
                    eproc = _x
                    break

        return super().run(curframe.f_locals)
