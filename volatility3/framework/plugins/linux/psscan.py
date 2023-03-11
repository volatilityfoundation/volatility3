# This file is Copyright 2023 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
import logging
from typing import Iterable, List, Tuple
import struct
from enum import Enum

from volatility3.framework import renderers, interfaces, symbols, constants, exceptions
from volatility3.framework.configuration import requirements
from volatility3.framework.objects import utility
from volatility3.framework.layers import scanners
from volatility3.framework.renderers import format_hints

vollog = logging.getLogger(__name__)


class DescExitStateEnum(Enum):
    """Enum for linux task exit_state as defined in include/linux/sched.h"""

    TASK_RUNNING = 0x00000000
    EXIT_DEAD = 0x00000010
    EXIT_ZOMBIE = 0x00000020
    EXIT_TRACE = EXIT_ZOMBIE | EXIT_DEAD


class PsScan(interfaces.plugins.PluginInterface):
    """Scans for processes present in a particular linux image."""

    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Linux kernel",
                architectures=["Intel32", "Intel64"],
            ),
        ]

    def _get_task_fields(
        self, task: interfaces.objects.ObjectInterface
    ) -> Tuple[int, int, int, str, str]:
        """Extract the fields needed for the final output

        Args:
            task: A task object from where to get the fields.
        Returns:
            A tuple with the fields to show in the plugin output.
        """
        pid = task.tgid
        tid = task.pid
        ppid = 0

        if task.parent.is_readable():
            ppid = task.parent.tgid
        name = utility.array_to_string(task.comm)
        exit_state = DescExitStateEnum(task.exit_state).name

        task_fields = (
            format_hints.Hex(task.vol.offset),
            pid,
            tid,
            ppid,
            name,
            exit_state,
        )
        return task_fields

    def _generator(self):
        """Generates the tasks found from scanning."""

        vmlinux_module_name = self.config["kernel"]
        vmlinux = self.context.modules[vmlinux_module_name]

        for task in self.scan_tasks(
            self.context, vmlinux_module_name, vmlinux.layer_name
        ):
            row = self._get_task_fields(task)
            yield (0, row)

    @classmethod
    def scan_tasks(
        cls,
        context: interfaces.context.ContextInterface,
        vmlinux_module_name: str,
        kernel_layer_name: str,
    ) -> Iterable[interfaces.objects.ObjectInterface]:
        """Scans for tasks in the memory layer.

        Args:
            context: The context to retrieve required elements (layers, symbol tables) from
            vmlinux_module_name: The name of the kernel module on which to operate
            kernel_layer_name: The name for the kernel layer
        Yields:
            Task objects
        """
        vmlinux = context.modules[vmlinux_module_name]

        # check if this image is 32bit or 64bit
        is_32bit = not symbols.symbol_table_is_64bit(context, vmlinux.symbol_table_name)
        if is_32bit:
            pack_format = "I"
        else:
            pack_format = "Q"
        # get task_struct to find the offset to the sched_class pointer
        sched_class_offset = vmlinux.get_type("task_struct").members["sched_class"][0]
        kernel_layer = context.layers[kernel_layer_name]

        needles = []
        for symbol in vmlinux.symbols:
            # find all sched_class names by searching by if they include '_sched_class', e.g. 'fair_sched_class'
            if "_sched_class" in symbol:
                # use canonicalize to set the appropriate sign extension for the addr
                addr = kernel_layer.canonicalize(
                    vmlinux.get_symbol(symbol).address + vmlinux.offset
                )
                packed_addr = struct.pack(pack_format, addr)

                # debug message to show needles being searched for and symbol names
                vollog.debug(
                    f"Found a sched_class named {symbol} at offset {hex(addr)}. Will scan for these bytes: {packed_addr.hex()}"
                )

                # append to needles list the packed hex for searching
                needles.append(packed_addr)
        # find the memory layer to scan
        if len(kernel_layer.dependencies) > 1:
            vollog.warning(
                f"Kernel layer depends on multiple layers however only {kernel_layer.dependencies[0]} will be scanned by this plugin."
            )
        elif len(kernel_layer.dependencies) == 0:
            vollog.error(
                f"Kernel layer has no dependencies, meaning there is no memory layer for this plugin to scan."
            )
            raise exceptions.LayerException(
                kernel_layer_name, f"Layer {kernel_layer_name} has no dependencies"
            )
        memory_layer_name = kernel_layer.dependencies[0]
        memory_layer = context.layers[kernel_layer.dependencies[0]]

        # scan the memory_layer for these needles
        for address, _ in memory_layer.scan(
            context, scanners.MultiStringScanner(needles)
        ):
            # create task in the memory_layer
            ptask = context.object(
                vmlinux.symbol_table_name + constants.BANG + "task_struct",
                offset=address - sched_class_offset,
                layer_name=memory_layer_name,
                native_layer_name=kernel_layer_name,
            )

            # sanity check exit_state
            try:
                # attempt tp parse the exist_state using the enum
                DescExitStateEnum(ptask.exit_state)
            except ValueError:
                vollog.debug(
                    f"Skipping task_struct at {hex(ptask.vol.offset)} as exit_state {ptask.exit_state} is likely not valid"
                )
                continue
            # sanity check pid
            if not (0 < ptask.pid < 65535):
                vollog.debug(
                    f"Skipping task_struct at {hex(ptask.vol.offset)} as pid {ptask.pid} is likely not valid"
                )
                continue
            yield ptask

    def run(self):
        columns = [
            ("OFFSET (P)", format_hints.Hex),
            ("PID", int),
            ("TID", int),
            ("PPID", int),
            ("COMM", str),
            ("EXIT_STATE", str),
        ]
        return renderers.TreeGrid(columns, self._generator())
