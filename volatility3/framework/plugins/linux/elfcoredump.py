# This file is Copyright 2026 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

import logging
from functools import partial
from typing import BinaryIO, List, Generator, Tuple

from volatility3.framework import renderers, interfaces
from volatility3.framework.configuration import requirements
from volatility3.framework.interfaces.layers import DataLayerInterface
from volatility3.framework.layers import intel
from volatility3.framework.objects import utility
from volatility3.framework.symbols.linux.utilities.coredumpwriter import CoreDumpWriter, PF_R, PF_W, PF_X
from volatility3.plugins.linux import proc, pslist

vollog = logging.getLogger(__name__)


class ElfCoreDump(interfaces.plugins.PluginInterface):
    """Creates a process core dump in ELF format containing the address space
       and segment names. Thread state is not included."""

    _required_framework_version = (2, 4, 0)
    _version = (1, 0, 0)

    MAX_VMA_SIZE = 1024 * 1024 * 1024  # Don't dump VMAs above 1 GB

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        # Since we're calling the plugin, make sure we have the plugin's requirements
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Linux kernel",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.IntRequirement(
                name="pid",
                description="Process ID to dump",
                optional=False,
            ),
            requirements.VersionRequirement(
                name="pslist", component=pslist.PsList, version=(4, 0, 0)
            ),
            requirements.VersionRequirement(
                name="proc", component=proc.Maps, version=(1, 0, 3)
            ),
        ]

    @staticmethod
    def prot_to_flags(prot: str) -> int:
        flags = 0
        if "r" in prot:
            flags |= PF_R
        if "w" in prot:
            flags |= PF_W
        if "x" in prot:
            flags |= PF_X

        return flags

    def write_segment_callback(
        self,
        proc_layer: DataLayerInterface,
        file_handle: BinaryIO,
        seg_start: int,
        seg_size: int
    ) -> None:
        chunk_size = 1024 * 1024 * 10
        offset = seg_start
        while offset < seg_start + seg_size:
            to_read = min(chunk_size, seg_start + seg_size - offset)
            data = proc_layer.read(offset, to_read, pad=True)
            if not data:
                break
            file_handle.write(data)
            offset += to_read

    def dump_process(self, task: interfaces.objects.ObjectInterface) -> str:
        parent_layer = self.context.layers[task.vol.layer_name]
        if not isinstance(parent_layer, intel.Intel):
            raise TypeError("Process parent layer is not a translation layer, unable to get bitness")

        writer = CoreDumpWriter(parent_layer.bits_per_register)
        for vma in proc.Maps.list_vmas(task):
            if not vma.vm_start or not vma.vm_end:
                continue
            if vma.vm_end - vma.vm_start > self.MAX_VMA_SIZE:
                vollog.debug(
                    f"VMA at 0x{vma.vm_start:x} over sanity-check size, not dumping"
                )
                continue

            vma_name = vma.get_name(self.context, task) or ""
            if not vma_name.startswith("/"):
                vma_name = ""  # only include real file mappings in the FILE note

            writer.add_segment(vma.vm_start,
                               vma.vm_end - vma.vm_start,
                               self.prot_to_flags(vma.get_protection()),
                               vma_name)

        proc_id = task.pid
        proc_layer_name = task.add_process_layer()
        proc_layer = self.context.layers[proc_layer_name]

        file = f"core.{proc_id}.elf"
        with open(file, "wb") as fp:
            writer.dump(fp, partial(self.write_segment_callback, proc_layer))

        return file

    def _generator(
        self, task: interfaces.objects.ObjectInterface
    ) -> Generator[
        Tuple[
            int,
            Tuple[
                int,
                str,
                str,
            ],
        ],
        None,
        None,
    ]:
        process_name = utility.array_to_string(task.comm)

        file = self.dump_process(task)

        yield (
            0,
            (
                task.pid,
                process_name,
                file,
            ),
        )

    def run(self) -> renderers.TreeGrid:
        filter_func = pslist.PsList.create_pid_filter([self.config.get("pid")])
        procs = list(pslist.PsList.list_tasks(
            self.context,
            self.config["kernel"],
            filter_func,
        ))
        if len(procs) != 1:
            raise Exception("Process not found")

        return renderers.TreeGrid(
            [
                ("PID", int),
                ("Process", str),
                ("File", str),
            ],
            self._generator(procs[0]),
        )
