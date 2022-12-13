# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
"""A module containing a collection of plugins that produce data typically
found in Linux's /proc file system."""

import logging
from typing import Callable, List, Generator, Iterable, Type, Optional

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
            requirements.PluginRequirement(
                name="pslist", plugin=pslist.PsList, version=(2, 0, 0)
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
                description="Process virtual memory address to include "
                "(all other address ranges are excluded). This must be "
                "a base address, not an address within the desired range.",
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
        ] = lambda _: False,
    ) -> Generator[interfaces.objects.ObjectInterface, None, None]:
        """Lists the Virtual Memory Areas of a specific process.

        Args:
            task: task object from which to list the vma
            filter_func: Function to take a vma and return True if it should be filtered out

        Returns:
            A list of vmas based on the task and filtered based on the filter function
        """
        if task.mm:
            for vma in task.mm.get_mmap_iter():
                if not filter_func(vma):
                    yield vma

    @classmethod
    def vma_dump(
        cls,
        context: interfaces.context.ContextInterface,
        task: interfaces.objects.ObjectInterface,
        vma: interfaces.objects.ObjectInterface,
        open_method: Type[interfaces.plugins.FileHandlerInterface],
        maxsize: int = MAXSIZE_DEFAULT,
    ) -> Optional[interfaces.plugins.FileHandlerInterface]:
        """Extracts the complete data for VMA as a FileInterface.

        Args:
            context: The context to retrieve required elements (layers, symbol tables) from
            task: an task_struct instance
            vma: The suspected VMA to extract (ObjectInterface)
            open_method: class to provide context manager for opening the file
            maxsize: Max size of VMA section (default MAXSIZE_DEFAULT)

        Returns:
            An open FileInterface object containing the complete data for the task or None in the case of failure
        """
        try:
            vm_start = vma.vm_start
            vm_end = vma.vm_end
        except AttributeError:
            vollog.debug("Unable to find the vm_start and vm_end")
            return None
        
        vm_size = vm_end - vm_start
        if 0 < maxsize < vm_size:
            vollog.debug(
                f"Skip virtual memory dump {vm_start:#x}-{vm_end:#x} due to maxsize limit"
            )
            return None

        pid = "Unknown"
        try:
            pid = task.tgid
            proc_layer_name = task.add_process_layer()
        except exceptions.InvalidAddressException as excp:
            vollog.debug(
                "Process {}: invalid address {} in layer {}".format(
                    pid, excp.invalid_address, excp.layer_name
                )
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
                if not data:
                    break
                file_handle.write(data)
                offset += to_read

        except Exception as excp:
            vollog.debug(f"Unable to dump virtual memory {file_name}: {excp}")
            return None

        return file_handle

    def _generator(self, tasks):
        # build filter for addresses if required
        address_list = self.config.get("address", [])
        if address_list == []:
            # do not filter as no address_list was supplied
            filter_func = lambda _: False 
        else:
            # filter for any vm_start that matches the supplied address config
            def filter_function(x: interfaces.objects.ObjectInterface) -> bool:
                return x.vm_start not in address_list

            filter_func = filter_function

        for task in tasks:
            if not task.mm:
                continue

            name = utility.array_to_string(task.comm)

            for vma in self.list_vmas(task, filter_func=filter_func):
                flags = vma.get_protection()
                page_offset = vma.get_page_offset()
                major = 0
                minor = 0
                inode = 0

                if vma.vm_file != 0:
                    dentry = vma.vm_file.get_dentry()
                    if dentry != 0:
                        inode_object = dentry.d_inode
                        major = inode_object.i_sb.major
                        minor = inode_object.i_sb.minor
                        inode = inode_object.i_ino

                path = vma.get_name(self.context, task)

                file_output = "Disabled"
                if self.config["dump"]:
                    file_handle = self.vma_dump(
                        self.context, task, vma, self.open, self.config["maxsize"]
                    )
                    file_output = "Error outputting file"
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
                        inode,
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
