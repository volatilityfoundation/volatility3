# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
"""A module containing a collection of plugins that produce data typically
found in Linux's /proc file system."""

import logging
from typing import Callable, Generator, Type, Optional

from volatility3.framework import renderers, interfaces, exceptions
from volatility3.framework.configuration import requirements
from volatility3.framework.interfaces import plugins
from volatility3.framework.objects import utility
from volatility3.framework.renderers import format_hints
from volatility3.plugins.linux import pslist

vollog = logging.getLogger(__name__)


class Maps(plugins.PluginInterface):
    """Lists all memory maps for all processes."""

    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 3)

    MAXSIZE_DEFAULT = 1024 * 1024 * 1024  # 1 Gb

    @classmethod
    def get_requirements(cls):
        # Since we're calling the plugin, make sure we have the plugin's requirements
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Linux kernel",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.VersionRequirement(
                name="pslist", component=pslist.PsList, version=(4, 0, 0)
            ),
            requirements.ListRequirement(
                name="pid",
                description="Filter on specific process IDs",
                element_type=int,
                optional=True,
            ),
            requirements.BooleanRequirement(
                name="dump",
                description="Extract listed memory segments",
                default=False,
                optional=True,
            ),
            requirements.ListRequirement(
                name="address",
                description="Process virtual memory addresses to include "
                "(all other VMA sections are excluded). This can be any "
                "virtual address within the VMA section.",
                element_type=int,
                optional=True,
            ),
            requirements.IntRequirement(
                name="maxsize",
                description="Maximum size for dumped VMA sections "
                "(all the bigger sections will be ignored)",
                default=cls.MAXSIZE_DEFAULT,
                optional=True,
            ),
        ]

    @classmethod
    def list_vmas(
        cls,
        task: interfaces.objects.ObjectInterface,
        filter_func: Callable[
            [interfaces.objects.ObjectInterface], bool
        ] = lambda _: True,
    ) -> Generator[interfaces.objects.ObjectInterface, None, None]:
        """Lists the Virtual Memory Areas of a specific process.

        Args:
            task: task object from which to list the vma
            filter_func: Function to take a vma and return False if it should be filtered out

        Returns:
            Yields vmas based on the task and filtered based on the filter function
        """
        mm_pointer = task.mm
        if not mm_pointer:
            vollog.debug(
                f"Excluded pid {task.pid} as there is no mm member. It is likely a kernel thread"
            )
            return

        if not mm_pointer.is_readable():
            vollog.error(f"Task {task.pid} has an invalid mm member")
            return

        for vma in mm_pointer.get_vma_iter():
            if filter_func(vma):
                yield vma
            else:
                vollog.debug(
                    f"Excluded vma at offset {vma.vol.offset:#x} for pid {task.pid} due to filter_func"
                )

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
        pid = task.pid

        try:
            proc_layer_name = task.add_process_layer()
        except exceptions.InvalidAddressException as excp:
            vollog.debug(
                f"Process {pid}: invalid address {excp.invalid_address} in layer {excp.layer_name}"
            )
            return None
        vm_size = vm_end - vm_start

        # check if vm_size is negative, this should never happen.
        if vm_size < 0:
            vollog.warning(
                f"Skip virtual memory dump for pid {pid} between {vm_start:#x}-{vm_end:#x} as {vm_size} is negative."
            )
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
                data = proc_layer.read(offset, to_read, pad=True)
                file_handle.write(data)
                offset += to_read
        except Exception as excp:
            vollog.debug(f"Unable to dump virtual memory {file_name}: {excp}")
            return None
        return file_handle

    def _generator(self, tasks):
        # build filter for addresses if required
        address_list = self.config.get("address", None)
        if not address_list:
            # do not filter as no address_list was supplied
            def vma_filter_func(_):
                return True

        else:
            # filter for any vm_start that matches the supplied address config
            def vma_filter_function(x: interfaces.objects.ObjectInterface) -> bool:
                addrs_in_vma = [
                    addr for addr in address_list if x.vm_start <= addr <= x.vm_end
                ]

                # if any of the user supplied addresses would fall within this vma return true
                return bool(addrs_in_vma)

            vma_filter_func = vma_filter_function

        for task in tasks:
            if not (task.mm and task.mm.is_readable()):
                continue
            name = utility.array_to_string(task.comm)

            for vma in self.list_vmas(task, filter_func=vma_filter_func):
                flags = vma.get_protection()
                page_offset = vma.get_page_offset()

                inode_num = None
                try:
                    dentry = vma.vm_file.get_dentry()
                    inode_ptr = dentry.d_inode
                    inode_num = inode_ptr.i_ino
                    major = inode_ptr.i_sb.major
                    minor = inode_ptr.i_sb.minor
                except exceptions.InvalidAddressException:
                    if not inode_num:
                        inode_num = 0
                    major = 0
                    minor = 0

                path = vma.get_name(self.context, task)

                file_output = "Disabled"
                if self.config["dump"]:
                    file_output = "Error outputting file"
                    try:
                        vm_start = vma.vm_start
                        vm_end = vma.vm_end
                    except AttributeError:
                        vollog.debug(
                            f"Unable to find the vm_start and vm_end for vma at {vma.vol.offset:#x} for pid {task.pid}"
                        )
                        vm_start = None
                        vm_end = None
                    if vm_start and vm_end:
                        # only attempt to dump the memory if we have vm_start and vm_end
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
                        task.pid,
                        name,
                        format_hints.Hex(vma.vm_start),
                        format_hints.Hex(vma.vm_end),
                        flags,
                        format_hints.Hex(page_offset),
                        major,
                        minor,
                        inode_num,
                        path or renderers.NotAvailableValue(),
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
                ("Flags", str),
                ("PgOff", format_hints.Hex),
                ("Major", int),
                ("Minor", int),
                ("Inode", int),
                ("File Path", str),
                ("File output", str),
            ],
            self._generator(
                pslist.PsList.list_tasks(
                    self.context, self.config["kernel"], filter_func=filter_func
                )
            ),
        )
