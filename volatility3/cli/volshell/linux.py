# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

from typing import Any, List, Tuple, Union

from volatility3.cli.volshell import generic
from volatility3.framework import constants, interfaces
from volatility3.framework.configuration import requirements
from volatility3.plugins.linux import pslist


class Volshell(generic.Volshell):
    """Shell environment to directly interact with a linux memory image."""

    @classmethod
    def get_requirements(cls):
        return [
            requirements.ModuleRequirement(
                name="kernel", description="Linux kernel module"
            ),
            requirements.PluginRequirement(
                name="pslist", plugin=pslist.PsList, version=(2, 0, 0)
            ),
            requirements.IntRequirement(
                name="pid", description="Process ID", optional=True
            ),
        ]

    def change_task(self, pid=None):
        """Change the current process and layer, based on a process ID"""
        tasks = self.list_tasks()
        for task in tasks:
            if task.pid == pid:
                process_layer = task.add_process_layer()
                if process_layer is not None:
                    self.change_layer(process_layer)
                    return
                print(f"Layer for task ID {pid} could not be constructed")
                return
        print(f"No task with task ID {pid} found")

    def list_tasks(self):
        """Returns a list of task objects from the primary layer"""
        # We always use the main kernel memory and associated symbols
        return list(pslist.PsList.list_tasks(self.context, self.current_kernel_name))

    def construct_locals(self) -> List[Tuple[List[str], Any]]:
        result = super().construct_locals()
        result += [
            (["ct", "change_task", "cp"], self.change_task),
            (["lt", "list_tasks", "ps"], self.list_tasks),
            (["symbols"], self.context.symbol_space[self.current_symbol_table]),
        ]
        if self.config.get("pid", None) is not None:
            self.change_task(self.config["pid"])
        return result

    def display_type(
        self,
        object: Union[
            str, interfaces.objects.ObjectInterface, interfaces.objects.Template
        ],
        offset: int = None,
    ):
        """Display Type describes the members of a particular object in alphabetical order"""
        if isinstance(object, str):
            if constants.BANG not in object:
                object = self.current_symbol_table + constants.BANG + object
        return super().display_type(object, offset)

    def display_symbols(self, symbol_table: str = None):
        """Prints an alphabetical list of symbols for a symbol table"""
        if symbol_table is None:
            symbol_table = self.current_symbol_table
        return super().display_symbols(symbol_table)

    @property
    def current_layer(self):
        if self.__current_layer is None:
            self.__current_layer = self.kernel.layer_name
        return self.__current_layer
