# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

from typing import Any, List, Optional, Tuple, Union
from enum import Enum

from volatility3.cli.volshell import generic
from volatility3.framework import constants, interfaces
from volatility3.framework.configuration import requirements
from volatility3.plugins.linux import pslist


# Could import the enum from psscan.py to avoid code duplication
class DescExitStateEnum(Enum):
    """Enum for linux task exit_state as defined in include/linux/sched.h"""

    TASK_RUNNING = 0x00000000
    EXIT_DEAD = 0x00000010
    EXIT_ZOMBIE = 0x00000020
    EXIT_TRACE = EXIT_ZOMBIE | EXIT_DEAD


class Volshell(generic.Volshell):
    """Shell environment to directly interact with a linux memory image."""

    @classmethod
    def get_requirements(cls):
        return [
            requirements.ModuleRequirement(
                name="kernel", description="Linux kernel module"
            ),
            requirements.VersionRequirement(
                name="pslist", component=pslist.PsList, version=(4, 0, 0)
            ),
            requirements.IntRequirement(
                name="pid", description="Process ID", optional=True
            ),
            requirements.VersionRequirement(
                name="generic_volshell",
                component=generic.Volshell,
                version=(1, 0, 0),
            ),
        ] + super().get_requirements()

    def change_task(self, pid=None):
        """Change the current process and layer, based on a process ID"""
        tasks = self.list_tasks()
        for task in tasks:
            if task.pid == pid:
                process_layer = task.add_process_layer()
                if process_layer is not None:
                    self.change_layer(process_layer)
                    return None
                print(f"Layer for task ID {pid} could not be constructed")
                return None
        print(f"No task with task ID {pid} found")

    def get_process(self, pid=None, virtaddr=None, physaddr=None):
        """Return the task_struct object that matches the pid. If a physical or a virtual address is provided, construct the task_struct object at said address. Only one parameter is allowed.

        Args:
            pid (int, optional): PID to search for
            virtaddr (int, optional): Virtual address to construct object at
            physaddr (int, optional): Physical address to construct object at

        Returns:
            ObjectInterface: task_struct Object
        """

        if sum(1 if x is not None else 0 for x in [pid, virtaddr, physaddr]) != 1:
            print("Only one parameter is accepted")
            return None

        vmlinux_module_name = self.config["kernel"]
        vmlinux = self.context.modules[vmlinux_module_name]

        kernel_layer_name = vmlinux.layer_name
        kernel_layer = self.context.layers[kernel_layer_name]

        memory_layer_name = kernel_layer.dependencies[0]

        task_struct_symbol = vmlinux.symbol_table_name + constants.BANG + "task_struct"

        if virtaddr is not None:
            task = self.context.object(
                task_struct_symbol,
                layer_name=kernel_layer_name,
                offset=virtaddr,
            )

        if physaddr is not None:
            task = self.context.object(
                task_struct_symbol,
                layer_name=memory_layer_name,
                offset=physaddr,
                native_layer_name=kernel_layer_name,
            )

        if physaddr is not None or virtaddr is not None:
            try:
                DescExitStateEnum(task.exit_state)
            except ValueError:
                print(
                    f"task_struct @ {hex(task.vol.offset)} as exit_state {task.exit_state} is likely not valid"
                )

            if not (0 < task.pid < 65535):
                print(
                    f"task_struct @ {hex(task.vol.offset)} as pid {task.pid} is likely not valid"
                )

            return task

        if pid is not None:
            tasks = self.list_tasks()
            for task in tasks:
                if task.pid == pid:
                    return task
            print(f"No task with task ID {pid} found")

        return None

    def list_tasks(self):
        """Returns a list of task objects from the primary layer"""
        # We always use the main kernel memory and associated symbols
        return list(pslist.PsList.list_tasks(self.context, self.current_kernel_name))

    def construct_locals(self) -> List[Tuple[List[str], Any]]:
        result = super().construct_locals()
        result += [
            (["ct", "change_task", "cp"], self.change_task),
            (["lt", "list_tasks", "ps"], self.list_tasks),
            (["gp", "get_process", "get_task"], self.get_process),
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
        offset: Optional[int] = None,
    ):
        """Display Type describes the members of a particular object in alphabetical order"""
        if isinstance(object, str):
            if constants.BANG not in object:
                object = self.current_symbol_table + constants.BANG + object
        return super().display_type(object, offset)

    def display_symbols(self, symbol_table: Optional[str] = None):
        """Prints an alphabetical list of symbols for a symbol table"""
        if symbol_table is None:
            symbol_table = self.current_symbol_table
        return super().display_symbols(symbol_table)

    @property
    def current_layer(self):
        if self.__current_layer is None:
            self.__current_layer = self.kernel.layer_name
        return self.__current_layer
