# This file is Copyright 2026 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

import logging
from functools import partial
from typing import BinaryIO, List, Generator, Tuple

from volatility3.framework import renderers, interfaces, exceptions
from volatility3.framework.configuration import requirements
from volatility3.framework.interfaces.layers import DataLayerInterface
from volatility3.framework.layers import intel
from volatility3.framework.objects import utility
from volatility3.framework.symbols.linux.utilities.coredumpwriter import CoreDumpWriter, PF_R, PF_W, PF_X
from volatility3.plugins.windows import pslist, vadinfo

vollog = logging.getLogger(__name__)


class ElfCoreDump(interfaces.plugins.PluginInterface):
    """Creates a process core dump in ELF format containing the address space
       and segment names. Thread state is not included."""

    _required_framework_version = (2, 4, 0)
    _version = (1, 0, 0)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        # Since we're calling the plugin, make sure we have the plugin's requirements
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Windows kernel",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.IntRequirement(
                name="pid",
                description="Process ID to dump",
                optional=False,
            ),
            requirements.VersionRequirement(
                name="pslist", component=pslist.PsList, version=(3, 0, 0)
            ),
            requirements.VersionRequirement(
                name="vadinfo", component=vadinfo.VadInfo, version=(2, 0, 1)
            ),
        ]

    @staticmethod
    def prot_to_flags(prot: str) -> int:
        flags = 0
        if "READ" in prot or "WRITECOPY" in prot:
            flags |= PF_R
        if "WRITE" in prot or "WRITECOPY" in prot:
            flags |= PF_W
        if "EXECUTE" in prot:
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

    def dump_process(self, proc: interfaces.objects.ObjectInterface) -> str:
        kernel = self.context.modules[self.config["kernel"]]

        parent_layer = self.context.layers[proc.vol.layer_name]
        if not isinstance(parent_layer, intel.Intel):
            raise TypeError("Process parent layer is not a translation layer, unable to get bitness")

        writer = CoreDumpWriter(parent_layer.bits_per_register)
        for vad in vadinfo.VadInfo.list_vads(proc):
            if vad.get_commit_charge() == 0 and \
                    isinstance(vad.get_file_name(), renderers.NotApplicableValue):
                continue

            writer.add_segment(vad.get_start(),
                               vad.get_size(),
                               self.prot_to_flags(vad.get_protection(
                                    vadinfo.VadInfo.protect_values(
                                        self.context,
                                        kernel.layer_name,
                                        kernel.symbol_table_name,
                                    ),
                                    vadinfo.winnt_protections,
                                )),
                               vad.get_file_name())

        try:
            proc_id = proc.UniqueProcessId
            proc_layer_name = proc.add_process_layer()
        except exceptions.InvalidAddressException as excp:
            raise Exception(f"Process {proc_id}: invalid address {excp.invalid_address}"
                            f" in layer {excp.layer_name}") from excp

        proc_layer = self.context.layers[proc_layer_name]

        file = f"core.{proc_id}.elf"
        with open(file, "wb") as fp:
            writer.dump(fp, partial(self.write_segment_callback, proc_layer))

        return file

    def _generator(
        self, proc: interfaces.objects.ObjectInterface
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
        process_name = utility.array_to_string(proc.ImageFileName)

        file = self.dump_process(proc)

        yield (
            0,
            (
                proc.UniqueProcessId,
                process_name,
                file,
            ),
        )

    def run(self) -> renderers.TreeGrid:
        filter_func = pslist.PsList.create_pid_filter([self.config.get("pid")])
        procs = list(pslist.PsList.list_processes(
            context=self.context,
            kernel_module_name=self.config["kernel"],
            filter_func=filter_func,
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
