# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl_v1.0
#

from typing import Dict, Any

from volatility.cli.volshell import shellplugin
from volatility.framework.configuration import requirements
from volatility.plugins.windows import pslist


class Volshell(shellplugin.Volshell):
    """Shell environment to directly interact with a windows memory image."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    @classmethod
    def get_requirements(cls):
        return (super().get_requirements() + [
            requirements.SymbolTableRequirement(name = "nt_symbols", description = "Windows kernel symbols"),
            requirements.PluginRequirement(name = 'pslist', plugin = pslist.PsList, version = (1, 0, 0)),
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
        print("No process with process ID {} found".format(pid))

    def list_processes(self):
        """Returns a list of EPROCESS objects from the primary layer"""
        # We always use the main kernel memory and the symbols
        return list(pslist.PsList.list_processes(self.context, self.config['primary'], self.config['nt_symbols']))

    def construct_locals(self) -> Dict[str, Any]:
        result = super().construct_locals()
        result.update({
            'cp': self.change_process,
            'change_process': self.change_process,
            'ps': self.list_processes,
            'list_processes': self.list_processes,
            'symbols': self.context.symbol_space[self.config['nt_symbols']]
        })
        if self.config.get('pid', None) is not None:
            self.change_process(self.config['pid'])
        return result
