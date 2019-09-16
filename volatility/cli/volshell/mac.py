# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl_v1.0
#

from typing import Dict, Any

from volatility.cli.volshell import shellplugin
from volatility.framework.configuration import requirements
from volatility.plugins.mac import pslist


class Volshell(shellplugin.Volshell):
    """Shell environment to directly interact with a mac memory image."""

    @classmethod
    def get_requirements(cls):
        return (super().get_requirements() + [
            requirements.SymbolTableRequirement(name = "darwin", description = "Darwin kernel symbols"),
            requirements.PluginRequirement(name = 'pslist', plugin = pslist.PsList, version = (1, 0, 0)),
            requirements.IntRequirement(name = 'pid', description = "Process ID", optional = True)
        ])

    def change_task(self, pid = None):
        """Change the current process and layer, based on a process ID"""
        tasks = self.list_tasks()
        for task in tasks:
            if task.p_pid == pid:
                process_layer = task.add_process_layer()
                if process_layer is not None:
                    self.change_layer(process_layer)
                    return
                print("Layer for task ID {} could not be constructed".format(pid))
                return
        print("No task with task ID {} found".format(pid))

    def list_tasks(self):
        """Returns a list of task objects from the primary layer"""
        # We always use the main kernel memory and associated symbols
        return list(pslist.PsList.list_tasks(self.context, self.config['primary'], self.config['darwin']))

    def construct_locals(self) -> Dict[str, Any]:
        result = super().construct_locals()
        result.update({
            'ct': self.change_task,
            'change_task': self.change_task,
            'lt': self.list_tasks,
            'list_tasks': self.list_tasks,
            'symbols': self.context.symbol_space[self.config['darwin']],
            # windows/windbg compatibility aliases
            'cp': self.change_task,
            'ps': self.list_tasks,
        })
        if self.config.get('pid', None) is not None:
            self.change_task(self.config['pid'])
        return result
