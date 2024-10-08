# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

from volatility3.framework import renderers, interfaces, exceptions
from volatility3.framework.configuration import requirements
from volatility3.framework.objects import utility
from volatility3.framework.renderers import format_hints
from volatility3.plugins.freebsd import pslist
from typing import Callable, Generator, Type, Optional
import logging

vollog = logging.getLogger(__name__)


class Maps(interfaces.plugins.PluginInterface):
    """Lists process memory ranges that potentially contain injected code."""

    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 0)
    MAXSIZE_DEFAULT = 1024 * 1024 * 1024  # 1 Gb

    @classmethod
    def get_requirements(cls):
        return [
            requirements.ModuleRequirement(
                name = "kernel",
                description = "Kernel module for the OS",
                architectures = ["Intel32", "Intel64"],
            ),
            requirements.PluginRequirement(name = "pslist", plugin = pslist.PsList, version = (1, 0, 0)),
            requirements.ListRequirement(
                name = "pid",
                description = "Filter on specific process IDs",
                element_type = int,
                optional = True,
            ),
            requirements.BooleanRequirement(
                name = "dump",
                description = "Extract listed memory segments",
                default = False,
                optional = True,
            ),
            requirements.ListRequirement(
                name = "address",
                description = "Process virtual memory addresses to include "
                "(all other VMA sections are excluded). This can be any "
                "virtual address within the VMA section. Virtual addresses "
                "must be separated by a space.",
                element_type = int,
                optional = True,
            ),
            requirements.IntRequirement(
                name = "maxsize",
                description = "Maximum size for dumped VMA sections "
                "(all the bigger sections will be ignored)",
                default = cls.MAXSIZE_DEFAULT,
                optional = True,
            ),
        ]

    @classmethod
    def list_vmas(
        cls,
        task: interfaces.objects.ObjectInterface,
        filter_func: Callable[[interfaces.objects.ObjectInterface], bool] = lambda _: True,
    ) -> Generator[interfaces.objects.ObjectInterface, None, None]:
        """Lists the Virtual Memory Areas of a specific process.

        Args:
            task: task object from which to list the vma
            filter_func: Function to take a vma and return False if it should be filtered out

        Returns:
            Yields vmas based on the task and filtered based on the filter function
        """
        for vma in task.get_map_iter():
            if filter_func(vma):
                yield vma
            else:
                vollog.debug(f"Excluded vma at offset {vma.vol.offset:#x} for pid {task.p_pid} due to filter_func")

    @classmethod
    def vma_dump(
        cls,
        context: interfaces.context.ContextInterface,
        task: interfaces.objects.ObjectInterface,
        vm_start: int,
        vm_end: int,
        open_method: Type[interfaces.plugins.FileHandlerInterface],
        maxsize: int = MAXSIZE_DEFAULT,
    ) -> Optional[interfaces.plugins.FileHandlerInterface]:
        """Extracts the complete data for VMA as a FileInterface.

        Args:
            context: The context to retrieve required elements (layers, symbol tables) from
            task: an task_struct instance
            vm_start: The start virtual address from the vma to dump
            vm_end: The end virtual address from the vma to dump
            open_method: class to provide context manager for opening the file
            maxsize: Max size of VMA section (default MAXSIZE_DEFAULT)

        Returns:
            An open FileInterface object containing the complete data for the task or None in the case of failure
        """
        pid = task.p_pid

        try:
            proc_layer_name = task.add_process_layer()
        except exceptions.InvalidAddressException as excp:
            vollog.debug("Process {}: invalid address {} in layer {}".format(pid, excp.invalid_address,
                                                                             excp.layer_name))
            return None
        vm_size = vm_end - vm_start

        # check if vm_size is negative, this should never happen.
        if vm_size < 0:
            vollog.warning(
                f"Skip virtual memory dump for pid {pid} between {vm_start:#x}-{vm_end:#x} as {vm_size} is negative.")
            return None
        # check if vm_size is larger than the maxsize limit, and therefore is not saved out.
        if maxsize <= vm_size:
            vollog.warning(
                f"Skip virtual memory dump for pid {pid} between {vm_start:#x}-{vm_end:#x} as {vm_size} is larger than maxsize limit of {maxsize}"
            )
            return None
        proc_layer = context.layers[proc_layer_name]
        file_name = f"pid.{pid}.vma.{vm_start:#x}-{vm_end:#x}.dmp"
        try:
            file_handle = open_method(file_name)
            chunk_size = 1024 * 1024 * 10
            offset = vm_start
            while offset < vm_start + vm_size:
                to_read = min(chunk_size, vm_start + vm_size - offset)
                data = proc_layer.read(offset, to_read, pad = True)
                file_handle.write(data)
                offset += to_read
        except Exception as excp:
            vollog.debug(f"Unable to dump virtual memory {file_name}: {excp}")
            return None
        return file_handle

    def _generator(self, tasks):
        address_list = self.config.get("address", None)
        if not address_list:
            # do not filter as no address_list was supplied
            vma_filter_func = lambda _: True
        else:
            # filter for any vm_start that matches the supplied address config
            def vma_filter_function(task: interfaces.objects.ObjectInterface) -> bool:
                addrs_in_vma = [addr for addr in address_list if task.start <= addr <= task.end]

                # if any of the user supplied addresses would fall within this vma return true
                return bool(addrs_in_vma)

            vma_filter_func = vma_filter_function

        for task in tasks:
            process_name = utility.array_to_string(task.p_comm)
            process_pid = task.p_pid

            for vma in self.list_vmas(task, filter_func = vma_filter_func):
                try:
                    vm_start = vma.start
                    vm_end = vma.end
                except AttributeError:
                    vollog.debug(
                        f"Unable to find the vm_start and vm_end for vma at {vma.vol.offset:#x} for pid {process_pid}")
                    continue

                path = vma.get_path(self.context.modules[self.config["kernel"]])

                file_output = "Disabled"
                if self.config["dump"]:
                    file_output = "Error outputting file"
                    file_handle = self.vma_dump(
                        self.context,
                        task,
                        vm_start,
                        vm_end,
                        self.open,
                        self.config["maxsize"],
                    )

                    if file_handle:
                        file_handle.close()
                        file_output = file_handle.preferred_filename

                yield (
                    0,
                    (
                        process_pid,
                        process_name,
                        format_hints.Hex(vm_start),
                        format_hints.Hex(vm_end),
                        vma.get_perms(),
                        path,
                        file_output,
                    ),
                )

    def run(self):
        filter_func = pslist.PsList.create_pid_filter(self.config.get("pid", None))

        return renderers.TreeGrid(
            [
                ("PID", int),
                ("Process", str),
                ("Start", format_hints.Hex),
                ("End", format_hints.Hex),
                ("Protection", str),
                ("Map Name", str),
                ("File output", str),
            ],
            self._generator(pslist.PsList.list_tasks(self.context, self.config["kernel"], filter_func = filter_func)),
        )
