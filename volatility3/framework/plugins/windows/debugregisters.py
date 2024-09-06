import logging

from typing import Tuple, Optional, Generator, List, Dict

from functools import partial

from volatility3.framework import renderers, interfaces, exceptions
from volatility3.framework.configuration import requirements
from volatility3.framework.renderers import format_hints
import volatility3.plugins.windows.pslist as pslist
import volatility3.plugins.windows.threads as threads
import volatility3.plugins.windows.pe_symbols as pe_symbols

vollog = logging.getLogger(__name__)


class DebugRegisters(interfaces.plugins.PluginInterface):
    # version 2.6.0 adds support for scanning for 'Ethread' structures by pool tags
    _required_framework_version = (2, 6, 0)
    _version = (1, 0, 0)

    @classmethod
    def get_requirements(cls) -> List:
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Windows kernel",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.VersionRequirement(
                name="pslist", component=pslist.PsList, version=(2, 0, 0)
            ),
            requirements.VersionRequirement(
                name="pe_symbols", component=pe_symbols.PESymbols, version=(1, 0, 0)
            ),
        ]

    def _get_debug_info(
        self, ethread: interfaces.objects.ObjectInterface
    ) -> Optional[Tuple[interfaces.objects.ObjectInterface, int, int, int, int, int]]:
        """
        Gathers information related to the debug registers for the given thread
        """
        try:
            dr7 = ethread.Tcb.TrapFrame.Dr7
            state = ethread.Tcb.State
        except exceptions.InvalidAddressException:
            return None

        # 0 = debug registers not active
        # 4 = terminated
        if dr7 == 0 or state == 4:
            return None

        try:
            owner_proc = ethread.owning_process()
        except (AttributeError, exceptions.InvalidAddressException):
            return None

        dr0 = ethread.Tcb.TrapFrame.Dr0
        dr1 = ethread.Tcb.TrapFrame.Dr1
        dr2 = ethread.Tcb.TrapFrame.Dr2
        dr3 = ethread.Tcb.TrapFrame.Dr3

        # bail if all are 0
        if not (dr0 or dr1 or dr2 or dr3):
            return None

        return owner_proc, dr7, dr0, dr1, dr2, dr3

    def _get_vads(
        self,
        vads_cache: Dict[int, List[Tuple[int, int, str]]],
        owner_proc: interfaces.objects.ObjectInterface,
    ) -> Optional[List[Tuple[int, int, str]]]:
        if owner_proc.vol.offset in vads_cache:
            vads = vads_cache[owner_proc.vol.offset]
        else:
            vads = pe_symbols.PESymbols.get_proc_vads_with_file_paths(owner_proc)
            vads_cache[owner_proc.vol.offset] = vads

        # smear or terminated process
        if len(vads) == 0:
            return None

        return vads

    def _generator(
        self,
    ) -> Generator[
        Tuple[
            int,
            Tuple[
                str,
                int,
                int,
                int,
                int,
                format_hints.Hex,
                str,
                str,
                format_hints.Hex,
                str,
                str,
                format_hints.Hex,
                str,
                str,
                format_hints.Hex,
                str,
                str,
            ],
        ],
        None,
        None,
    ]:
        kernel = self.context.modules[self.config["kernel"]]

        vads_cache: Dict[int, List[Tuple[int, int, str]]] = {}

        proc_modules = None

        procs = pslist.PsList.list_processes(
            context=self.context,
            layer_name=kernel.layer_name,
            symbol_table=kernel.symbol_table_name,
        )

        for proc in procs:
            for thread in threads.Threads.list_threads(kernel, proc):
                debug_info = self._get_debug_info(thread)
                if not debug_info:
                    continue

                owner_proc, dr7, dr0, dr1, dr2, dr3 = debug_info

                vads = self._get_vads(vads_cache, owner_proc)
                if not vads:
                    continue

                # this lookup takes a while, so only perform if we need to
                if not proc_modules:
                    proc_modules = pe_symbols.PESymbols.get_process_modules(
                        self.context, kernel.layer_name, kernel.symbol_table_name, None
                    )
                    path_and_symbol = partial(
                        pe_symbols.PESymbols.path_and_symbol_for_address,
                        self.context,
                        self.config_path,
                        proc_modules,
                    )

                file0, sym0 = path_and_symbol(vads, dr0)
                file1, sym1 = path_and_symbol(vads, dr1)
                file2, sym2 = path_and_symbol(vads, dr2)
                file3, sym3 = path_and_symbol(vads, dr3)

                # if none map to an actual file VAD then bail
                if not (
                    isinstance(file0, str)
                    or isinstance(file1, str)
                    or isinstance(file2, str)
                    or isinstance(file3, str)
                ):
                    continue

                process_name = owner_proc.ImageFileName.cast(
                    "string",
                    max_length=owner_proc.ImageFileName.vol.count,
                    errors="replace",
                )

                thread_tid = thread.Cid.UniqueThread

                yield (
                    0,
                    (
                        process_name,
                        owner_proc.UniqueProcessId,
                        thread_tid,
                        thread.Tcb.State,
                        dr7,
                        format_hints.Hex(dr0),
                        file0,
                        sym0,
                        format_hints.Hex(dr1),
                        file1,
                        sym1,
                        format_hints.Hex(dr2),
                        file2,
                        sym2,
                        format_hints.Hex(dr3),
                        file3,
                        sym3,
                    ),
                )

    def run(self) -> renderers.TreeGrid:
        return renderers.TreeGrid(
            [
                ("Process", str),
                ("PID", int),
                ("TID", int),
                ("State", int),
                ("Dr7", int),
                ("Dr0", format_hints.Hex),
                ("Range0", str),
                ("Symbol0", str),
                ("Dr1", format_hints.Hex),
                ("Range1", str),
                ("Symbol1", str),
                ("Dr2", format_hints.Hex),
                ("Range2", str),
                ("Symbol2", str),
                ("Dr3", format_hints.Hex),
                ("Range3", str),
                ("Symbol3", str),
            ],
            self._generator(),
        )
