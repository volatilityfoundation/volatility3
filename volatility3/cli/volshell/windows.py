# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

from typing import Any, List, Tuple, Union

from volatility3.cli.volshell import generic
from volatility3.framework import interfaces, constants
from volatility3.framework.configuration import requirements
from volatility3.plugins.windows import pslist


class Volshell(generic.Volshell):
    """Shell environment to directly interact with a windows memory image."""

    @classmethod
    def get_requirements(cls):
        return (super().get_requirements() + [
            requirements.SymbolTableRequirement(name = "nt_symbols", description = "Windows kernel symbols"),
            requirements.PluginRequirement(name = 'pslist', plugin = pslist.PsList, version = (2, 0, 0)),
            requirements.IntRequirement(name = 'pid', description = "Process ID", optional = True)
        ])

    def change_process(self, pid = None):
        """Change the current process and layer, based on a process ID"""
        processes = self.list_processes()
        for process in processes:
            if process.UniqueProcessId == pid:
                process_layer = process.add_process_layer()
                self.change_layer(process_layer)
                return
        print(f"No process with process ID {pid} found")

    def list_processes(self):
        """Returns a list of EPROCESS objects from the primary layer"""
        # We always use the main kernel memory and associated symbols
        return list(pslist.PsList.list_processes(self.context, self.config['primary'], self.config['nt_symbols']))

    def construct_locals(self) -> List[Tuple[List[str], Any]]:
        result = super().construct_locals()
        result += [
            (['cp', 'change_process'], self.change_process),
            (['lp', 'list_processes', 'ps'], self.list_processes),
            (['symbols'], self.context.symbol_space[self.config['nt_symbols']]),
        ]
        if self.config.get('pid', None) is not None:
            self.change_process(self.config['pid'])
        return result

    def display_type(self,
                     object: Union[str, interfaces.objects.ObjectInterface, interfaces.objects.Template],
                     offset: int = None):
        """Display Type describes the members of a particular object in alphabetical order"""
        if isinstance(object, str):
            if constants.BANG not in object:
                object = self.config['nt_symbols'] + constants.BANG + object
        return super().display_type(object, offset)

    def display_symbols(self, symbol_table: str = None):
        """Prints an alphabetical list of symbols for a symbol table"""
        if symbol_table is None:
            symbol_table = self.config['nt_symbols']
        return super().display_symbols(symbol_table)
