# This file is Copyright 2024 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

import logging
from typing import Iterable, Tuple

from volatility3.framework import interfaces, renderers, constants, exceptions
from volatility3.framework.configuration import requirements
from volatility3.framework.renderers import format_hints
from volatility3.framework.objects import utility
from volatility3.framework.symbols import intermed
from volatility3.framework.symbols.linux.extensions import elf
from volatility3.plugins.linux import pslist


vollog = logging.getLogger(__name__)


class LibraryList(interfaces.plugins.PluginInterface):
    """Enumerate libraries loaded into processes"""

    _required_framework_version = (2, 0, 0)

    _version = (1, 0, 0)

    @classmethod
    def get_requirements(cls):
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Linux kernel",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.PluginRequirement(
                name="pslist", plugin=pslist.PsList, version=(2, 2, 0)
            ),
            requirements.ListRequirement(
                name="pids",
                description="Filter on specific process IDs",
                element_type=int,
                optional=True,
            ),
        ]

    def get_libdl_libraries(
        self, proc_layer_name: str, vma_start: int
    ) -> interfaces.objects.ObjectInterface:
        """Get the ELF link map objects for the given VMA address

        Args:
            proc_layer_name (str): Name of the process layer
            vma_start (int): VMA start address

        Yields:
            ELF link map objects for the given VMA address
        """
        elf_table_name = intermed.IntermediateSymbolTable.create(
            self.context,
            self.config_path,
            "linux",
            "elf",
            class_types=elf.class_types,
        )
        elf_object = self.context.object(
            elf_table_name + constants.BANG + "Elf",
            offset=vma_start,
            layer_name=proc_layer_name,
        )

        if not elf_object or not elf_object.is_valid():
            return None

        kernel = self.context.modules[self.config["kernel"]]

        try:
            for link_map in elf_object.get_link_maps(kernel.symbol_table_name):
                if link_map.l_addr and link_map.l_name:
                    yield link_map
        except exceptions.InvalidAddressException:
            # Protection against memory smear in this VMA
            pass

    def get_libdl_maps(
        self, task: interfaces.objects.ObjectInterface, proc_layer_name: str
    ) -> interfaces.objects.ObjectInterface:
        """Get the ELF link maps objects for a task

        Args:
            task (task_struct): A reference task
            proc_layer_name (str): Name of the process layer

        Yields:
            ELF link map objects
        """

        link_map_seen = set()
        for vma in task.mm.get_vma_iter():
            for link_map in self.get_libdl_libraries(proc_layer_name, vma.vm_start):
                if link_map.l_addr in link_map_seen:
                    continue

                yield link_map
                link_map_seen.add(link_map.l_addr)

    def get_task_libraries(
        self, task: interfaces.objects.ObjectInterface
    ) -> Tuple[int, str]:
        """Get the task libraries from the ELF headers found within the memory maps

        Args:
            task (task_struct): The reference task

        Yields:
            Tuples with a ELF link map address and name
        """
        proc_layer_name = task.add_process_layer()
        if not proc_layer_name:
            return

        for elf_link_map in self.get_libdl_maps(task, proc_layer_name):
            name = elf_link_map.get_name()
            if not name:
                continue
            yield elf_link_map.l_addr, name

    def get_tasks_libraries(
        self,
        tasks: Iterable[interfaces.objects.ObjectInterface],
    ) -> Iterable[Tuple[str, int, int, str]]:
        """Get the task libraries from the ELF headers found within the memory maps for
        all the tasks.

        Args:
            tasks: An iterable of tasks

        Yields:
            Tuples with a task name, task tgid, an ELF link map address and name
        """
        for task in tasks:
            task_name = utility.array_to_string(task.comm)
            for linkmap_addr, linkmap_name in self.get_task_libraries(task):
                yield task_name, task.tgid, linkmap_addr, linkmap_name

    def _format_fields(self, fields):
        task_name, task_pid, addr, name = fields
        return task_name, task_pid, format_hints.Hex(addr), name

    def _generator(
        self, tasks: Iterable[interfaces.objects.ObjectInterface]
    ) -> Iterable[Tuple[int, Tuple]]:
        for fields in self.get_tasks_libraries(tasks):
            yield 0, self._format_fields(fields)

    def run(self):
        pids = self.config.get("pids")
        pid_filter = pslist.PsList.create_pid_filter(pids)
        tasks = pslist.PsList.list_tasks(
            self.context, self.config["kernel"], filter_func=pid_filter
        )

        headers = [
            ("Name", str),
            ("Pid", int),
            ("LoadAddress", format_hints.Hex),
            ("Path", str),
        ]

        return renderers.TreeGrid(headers, self._generator(tasks))
