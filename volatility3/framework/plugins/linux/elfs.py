# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
"""A module containing a collection of plugins that produce data typically
found in Linux's /proc file system."""

import logging
from typing import List, Optional, Type

from volatility3.framework import constants, interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.interfaces import plugins
from volatility3.framework.objects import utility
from volatility3.framework.renderers import format_hints
from volatility3.framework.symbols import intermed
from volatility3.framework.symbols.linux.extensions import elf
from volatility3.framework.constants.linux import ELF_MAX_EXTRACTION_SIZE
from volatility3.plugins.linux import pslist


vollog = logging.getLogger(__name__)


class Elfs(plugins.PluginInterface):
    """Lists all memory mapped ELF files for all processes."""

    _required_framework_version = (2, 0, 0)
    _version = (2, 0, 1)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
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
                description="Extract listed processes",
                default=False,
                optional=True,
            ),
        ]

    @classmethod
    def elf_dump(
        cls,
        context: interfaces.context.ContextInterface,
        layer_name: str,
        elf_table_name: str,
        vma: interfaces.objects.ObjectInterface,
        task: interfaces.objects.ObjectInterface,
        open_method: Type[interfaces.plugins.FileHandlerInterface],
    ) -> Optional[interfaces.plugins.FileHandlerInterface]:
        """Extracts an ELF as a FileHandlerInterface
        Args:
            context: the context to operate upon
            layer_name: The name of the layer on which to operate
            elf_table_name: the name for the symbol table containing the symbols for ELF-files
            vma: virtual memory allocation of ELF
            task: the task object whose memory should be output
            open_method: class to provide context manager for opening the file
        Returns:
            An open FileHandlerInterface object containing the complete data for the task or None in the case of failure
        """

        proc_layer = context.layers[layer_name]
        file_handle = None

        elf_object = context.object(
            elf_table_name + constants.BANG + "Elf",
            offset=vma.vm_start,
            layer_name=layer_name,
        )

        if not elf_object.is_valid():
            return None

        sections = {}
        # TODO: Apply more effort to reconstruct ELF, e.g.: https://github.com/enbarberis/core2ELF64 ?
        for phdr in elf_object.get_program_headers():
            try:
                if phdr.p_type.description != "PT_LOAD":
                    continue
            except ValueError:
                continue

            start = phdr.p_vaddr
            size = phdr.p_memsz
            end = start + size

            # Use complete memory pages for dumping
            # If start isn't a multiple of a page, stick to the highest multiple < start
            # If end isn't a multiple of a page, stick to the lowest multiple > end
            if start % proc_layer.page_size:
                start = start & proc_layer.page_mask

            if end % proc_layer.page_size:
                end = (end & proc_layer.page_mask) + proc_layer.page_size

            real_size = end - start

            # Check if ELF has a legitimate size
            if real_size < 0 or real_size > ELF_MAX_EXTRACTION_SIZE:
                raise ValueError(f"The claimed size of the ELF is invalid: {real_size}")

            sections[start] = real_size

        elf_data = b""
        for section_start in sorted(sections.keys()):
            read_size = sections[section_start]

            buf = proc_layer.read(vma.vm_start + section_start, read_size, pad=True)
            elf_data = elf_data + buf

        file_handle = open_method(
            f"pid.{task.pid}.{utility.array_to_string(task.comm)}.{vma.vm_start:#x}.dmp"
        )
        file_handle.write(elf_data)

        return file_handle

    def _generator(self, tasks):
        elf_table_name = intermed.IntermediateSymbolTable.create(
            self.context, self.config_path, "linux", "elf", class_types=elf.class_types
        )
        for task in tasks:
            proc_layer_name = task.add_process_layer()
            if not proc_layer_name:
                continue

            proc_layer = self.context.layers[proc_layer_name]

            name = utility.array_to_string(task.comm)

            for vma in task.mm.get_vma_iter():
                hdr = proc_layer.read(vma.vm_start, 4, pad=True)
                if hdr != b"\x7fELF":
                    continue

                path = vma.get_name(self.context, task)

                file_output = "Disabled"
                if self.config["dump"]:
                    file_handle = self.elf_dump(
                        self.context,
                        proc_layer_name,
                        elf_table_name,
                        vma,
                        task,
                        self.open,
                    )
                    file_output = "Error outputting file"
                    if file_handle:
                        file_handle.close()
                        file_output = str(file_handle.preferred_filename)

                yield (
                    0,
                    (
                        task.pid,
                        name,
                        format_hints.Hex(vma.vm_start),
                        format_hints.Hex(vma.vm_end),
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
                ("File Path", str),
                ("File Output", str),
            ],
            self._generator(
                pslist.PsList.list_tasks(
                    self.context, self.config["kernel"], filter_func=filter_func
                )
            ),
        )
