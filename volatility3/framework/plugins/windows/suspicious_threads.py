# This file is Copyright 2024 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

import logging
from typing import List, Dict, Tuple, Generator
from volatility3.framework import renderers, interfaces
from volatility3.framework.configuration import requirements
from volatility3.framework.objects import utility
from volatility3.framework.renderers import format_hints
from volatility3.plugins.windows import pslist, threads, vadinfo, thrdscan

vollog = logging.getLogger(__name__)


class SupsiciousThreads(interfaces.plugins.PluginInterface):
    """Lists suspicious userland process threads"""

    _required_framework_version = (2, 4, 0)
    _version = (2, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        # Since we're calling the plugin, make sure we have the plugin's requirements
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Windows kernel",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.ListRequirement(
                name="pid",
                description="Filter on specific process IDs",
                element_type=int,
                optional=True,
            ),
            requirements.PluginRequirement(
                name="threads", plugin=threads.Threads, version=(1, 0, 0)
            ),
            requirements.VersionRequirement(
                name="vadinfo", component=vadinfo.VadInfo, version=(2, 0, 0)
            ),
        ]

    def _get_ranges(
        self,
        kernel: interfaces.context.ModuleInterface,
        all_ranges: Dict[int, List[Tuple[int, int, str, str]]],
        proc,
    ) -> Tuple[int, int, str, str]:
        """
        Maintains a hash table so each process' VADs
        are only enumerated once per plugin run
        """
        key = proc.vol.offset

        if key not in all_ranges:
            all_ranges[key] = []

            for vad in proc.get_vad_root().traverse():
                fn = vad.get_file_name()
                if not isinstance(fn, str) or not fn:
                    fn = None

                protection_string = vad.get_protection(
                    vadinfo.VadInfo.protect_values(
                        self.context, kernel.layer_name, kernel.symbol_table_name
                    ),
                    vadinfo.winnt_protections,
                )

                all_ranges[key].append(
                    (vad.get_start(), vad.get_end(), protection_string, fn)
                )

        return all_ranges[key]

    def _get_range(
        self, ranges: Dict[int, List[Tuple[int, int, str, str]]], address: int
    ) -> Tuple[int, str, str]:
        """
        Walks a process' VADs looking for the one
        containing `address`

        Returns its base address, protection string, and mapped file, if any
        """
        for start, end, protection_string, fn in ranges:
            if start <= address < end:
                return start, protection_string, fn

        return None, None, None

    def _check_thread_address(
        self, exe_path: str, ranges, thread_address: int
    ) -> Generator[Tuple[str, str], None, None]:
        vad_base, prot, vad_path = self._get_range(ranges, thread_address)

        # threads outside of a VAD means either smear from this thread or this process' VAD tree
        if vad_base is None:
            return

        if vad_path is None:
            # set this so checks after report the non file backed region in the path column
            vad_path = "<Non-File Backed Region>"

            yield (
                vad_path,
                f"This thread started execution in the VAD starting at base address ({vad_base:#x}), which is not backed by a file",
            )

        # All threads should point to PAGE_EXECUTE_WRITECOPY mapped regions
        if prot != "PAGE_EXECUTE_WRITECOPY":
            yield (
                vad_path,
                f"VAD at base address ({vad_base:#x}) hosting this thread has an unexpected starting protection {prot}",
            )

        # check for process hollowing type techniques that mapped in a second, malicious exe file
        if (
            exe_path
            and vad_path.lower().endswith(".exe")
            and (vad_path.lower() != exe_path.lower())
        ):
            yield (
                vad_path,
                "VAD at base address ({vad_base:#x}) hosting this thread maps an application executable that is not the process exectuable",
            )

    def _enumerate_processes(
        self, kernel: interfaces.context.ModuleInterface, all_ranges
    ):
        filter_func = pslist.PsList.create_pid_filter(self.config.get("pid", None))

        for proc in pslist.PsList.list_processes(
            context=self.context,
            layer_name=kernel.layer_name,
            symbol_table=kernel.symbol_table_name,
            filter_func=filter_func,
        ):
            ranges = self._get_ranges(kernel, all_ranges, proc)

            # smeared vads or process is terminating
            if len(all_ranges[proc.vol.offset]) < 5:
                continue

            pid = proc.UniqueProcessId
            proc_name = utility.array_to_string(proc.ImageFileName)

            _, __, exe_path = self._get_range(ranges, proc.SectionBaseAddress)
            if not isinstance(exe_path, str):
                exe_path = None

            yield proc, pid, proc_name, exe_path, ranges

    def _generator(self):
        kernel = self.context.modules[self.config["kernel"]]

        all_ranges = {}

        for proc, pid, proc_name, exe_path, ranges in self._enumerate_processes(
            kernel, all_ranges
        ):
            # processes often create multiple threads at the same address
            # there is no benefit to checking the same address more than once per process
            checked = set()

            for thread in threads.Threads.list_threads(kernel, proc):
                # do not process if a thread is exited or terminated (4 = Terminated)
                if thread.ExitTime.QuadPart > 0 or thread.Tcb.State == 4:
                    continue

                # bail if accessing the threads members causes a page fault
                info = thrdscan.ThrdScan.gather_thread_info(thread)
                if not info:
                    continue

                _, _, tid, start_address, _, _ = info

                addresses = [
                    (start_address, "Start"),
                    (thread.Win32StartAddress, "Win32Start"),
                ]

                for address, context in addresses:
                    if address in checked:
                        continue
                    checked.add(address)

                    for vad_path, note in self._check_thread_address(
                        exe_path, ranges, address
                    ):
                        yield 0, (
                            proc_name,
                            pid,
                            tid,
                            context,
                            format_hints.Hex(address),
                            vad_path,
                            note,
                        )

    def run(self):
        return renderers.TreeGrid(
            [
                ("Process", str),
                ("PID", int),
                ("TID", int),
                ("Context", str),
                ("Address", format_hints.Hex),
                ("VAD Path", str),
                ("Note", str),
            ],
            self._generator(),
        )
