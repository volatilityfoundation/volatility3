import logging

from typing import Dict
import functools

from volatility3.framework import renderers, interfaces, exceptions
from volatility3.framework.configuration import requirements
from volatility3.framework.renderers import format_hints
import volatility3.plugins.windows.pslist as pslist
import volatility3.plugins.windows.threads as threads
import volatility3.plugins.windows.pe_symbols as pe_symbols

from volatility3.framework.objects import utility

vollog = logging.getLogger(__name__)


class SuspendedThreads(interfaces.plugins.PluginInterface):
    """Enumerates suspended threads."""

    _required_framework_version = (2, 13, 0)
    _version = (1, 0, 0)

    @classmethod
    def get_requirements(cls):
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Windows kernel",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.VersionRequirement(
                name="pslist", component=pslist.PsList, version=(3, 0, 0)
            ),
            requirements.VersionRequirement(
                name="pe_symbols", component=pe_symbols.PESymbols, version=(3, 0, 0)
            ),
            requirements.VersionRequirement(
                name="threads", component=threads.Threads, version=(3, 0, 0)
            ),
        ]

    def _generator(self):
        """
        The goal of this plugin is to report on threads that are suspended

        Legitimate programs can start threads suspended but then will later resume them

        Subsets of malware techniques, such as EDR evasion and process hollowing,
        create suspended threads and do not resume them. These are the threads that this
        plugin is designed to catch.

        See the whitepaper from our DEF CON 2024 presentation for more details:

        https://www.volexity.com/wp-content/uploads/2024/08/Defcon24_EDR_Evasion_Detection_White-Paper_Andrew-Case.pdf
        """
        vads_cache: Dict[int, pe_symbols.PESymbols.ranges_type] = {}

        proc_modules = None

        # walk the threads of each process checking for suspended threads
        for proc in pslist.PsList.list_processes(
            context=self.context, kernel_module_name=self.config["kernel"]
        ):
            for thread in threads.Threads.list_threads(
                self.context, self.config["kernel"], proc
            ):
                try:
                    # we only care if the thread is suspended
                    if thread.Tcb.SuspendCount == 0:
                        continue

                    # 4 == terminated
                    if thread.Tcb.State == 4:
                        continue

                    owner_proc = thread.owning_process()
                    owner_proc_pid = thread.Cid.UniqueProcess
                    owner_proc_name = utility.array_to_string(owner_proc.ImageFileName)
                    thread_tid = thread.Cid.UniqueThread
                    thread_start_addr = thread.StartAddress
                    thread_win32_addr = thread.Win32StartAddress
                except exceptions.InvalidAddressException:
                    continue

                # Nothing useful to report if a process doesn't have VADs.. Also a sign of smear/terminated
                vads = pe_symbols.PESymbols.get_vads_for_process_cache(
                    vads_cache, owner_proc
                )
                if not vads:
                    continue

                # Only compute this if needed as its expensive and 99.9% of samples
                # will not have suspended threads
                if not proc_modules:
                    proc_modules = pe_symbols.PESymbols.get_process_modules(
                        context=self.context,
                        kernel_module_name=self.config["kernel"],
                        filter_modules=None,
                    )

                    path_and_symbol = functools.partial(
                        pe_symbols.PESymbols.path_and_symbol_for_address,
                        self.context,
                        self.config_path,
                        proc_modules,
                    )

                start_file, start_sym = path_and_symbol(vads, thread_start_addr)
                win32_file, win32_sym = path_and_symbol(vads, thread_win32_addr)

                # the only false positive found in mass scanning of samples
                if start_file and start_file.endswith("\\WorkFoldersShell.dll"):
                    continue

                if win32_file and win32_file.endswith("\\WorkFoldersShell.dll"):
                    continue

                yield (
                    0,
                    (
                        owner_proc_name,
                        owner_proc_pid,
                        thread_tid,
                        start_file or renderers.NotAvailableValue(),
                        start_sym or renderers.NotAvailableValue(),
                        format_hints.Hex(thread_start_addr),
                        win32_file or renderers.NotAvailableValue(),
                        win32_sym or renderers.NotAvailableValue(),
                        format_hints.Hex(thread_win32_addr),
                    ),
                )

    def run(self):
        return renderers.TreeGrid(
            [
                ("Process", str),
                ("PID", int),
                ("TID", int),
                ("StartFile", str),
                ("StartSymbol", str),
                ("StartAddress", format_hints.Hex),
                ("Win32StartFile", str),
                ("Win32StartSymbol", str),
                ("Win32StartAddress", format_hints.Hex),
            ],
            self._generator(),
        )
