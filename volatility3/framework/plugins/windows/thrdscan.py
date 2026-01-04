##
## plugin for testing addition of threads scan support to poolscanner.py
##
import datetime
import logging
from typing import Callable, Dict, NamedTuple, Optional, Union, Tuple, Iterator

from volatility3.framework import exceptions, interfaces, objects, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.constants import windows as windows_constants
from volatility3.framework.renderers import format_hints
from volatility3.framework.symbols.windows import extensions as win_extensions
from volatility3.plugins import timeliner
from volatility3.plugins.windows import pe_symbols, poolscanner

vollog = logging.getLogger(__name__)


class ThrdScan(interfaces.plugins.PluginInterface, timeliner.TimeLinerInterface):
    """Scans for windows threads."""

    # version 2.6.0 adds support for scanning for 'Ethread' structures by pool tags
    _required_framework_version = (2, 6, 0)
    _version = (2, 1, 0)

    class ThreadInfo(NamedTuple):
        offset: int
        pid: objects.Pointer
        tid: objects.Pointer
        start_addr: objects.Pointer
        start_path: Optional[str]
        win32_start_addr: objects.Pointer
        win32_start_path: Optional[str]
        create_time: Union[datetime.datetime, interfaces.renderers.BaseAbsentValue]
        exit_time: Union[datetime.datetime, interfaces.renderers.BaseAbsentValue]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.implementation = self.scan_threads

    @classmethod
    def get_requirements(cls):
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Windows kernel",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.VersionRequirement(
                name="poolscanner", component=poolscanner.PoolScanner, version=(3, 0, 0)
            ),
            requirements.VersionRequirement(
                name="pe_symbols", component=pe_symbols.PESymbols, version=(3, 0, 0)
            ),
            requirements.VersionRequirement(
                name="timeliner",
                component=timeliner.TimeLinerInterface,
                version=(1, 0, 0),
            ),
        ]

    @classmethod
    def scan_threads(
        cls,
        context: interfaces.context.ContextInterface,
        module_name: str,
    ) -> Iterator[win_extensions.ETHREAD]:
        """Scans for threads using the poolscanner module and constraints.

        Args:
            context: The context to retrieve required elements (layers, symbol tables) from
            module_name: Name of the module to use for scanning

        Returns:
              A list of _ETHREAD objects found by scanning memory for the "Thre" / "Thr\\xE5" pool signatures
        """

        kernel = context.modules[module_name]

        constraints = poolscanner.PoolScanner.builtin_constraints(
            kernel.symbol_table_name, [b"Thr\xe5", b"Thre"]
        )

        for result in poolscanner.PoolScanner.generate_pool_scan(
            context, module_name, constraints
        ):
            _constraint, mem_object, _header = result
            yield mem_object

    @classmethod
    def gather_thread_info(
        cls,
        ethread: win_extensions.ETHREAD,
        vads_cache: Optional[Dict[int, pe_symbols.ranges_type]] = None,
    ) -> Optional[ThreadInfo]:
        try:
            thread_offset = ethread.vol.offset
            owner_proc_pid = ethread.Cid.UniqueProcess
            thread_tid = ethread.Cid.UniqueThread
            thread_start_addr = ethread.StartAddress
            thread_win32start_addr = ethread.Win32StartAddress
            thread_create_time = (
                ethread.get_create_time()
            )  # datetime.datetime object / volatility3.framework.renderers.UnparsableValue object
            thread_exit_time = (
                ethread.get_exit_time()
            )  # datetime.datetime object / volatility3.framework.renderers.UnparsableValue object

            owner_proc = None
            if vads_cache is not None:
                owner_proc = ethread.owning_process()
        except exceptions.InvalidAddressException:
            vollog.debug(f"Thread invalid address {ethread.vol.offset:#x}")
            return None

        # Filter junk PIDs
        if (
            ethread.Cid.UniqueProcess > windows_constants.MAX_PID
            or ethread.Cid.UniqueProcess == 0
            or ethread.Cid.UniqueProcess % 4 != 0
        ):
            return None

        # Get VAD mappings for valid non-system (PID 4) processes
        if (
            owner_proc
            and owner_proc.is_valid()
            and owner_proc.UniqueProcessId != 4
            and vads_cache is not None
        ):
            vads = pe_symbols.PESymbols.get_vads_for_process_cache(
                vads_cache, owner_proc
            )

            start_path = (
                pe_symbols.PESymbols.filepath_for_address(vads, thread_start_addr)
                if vads
                else None
            )
            win32start_path = (
                pe_symbols.PESymbols.filepath_for_address(vads, thread_win32start_addr)
                if vads
                else None
            )
        else:
            start_path = None
            win32start_path = None

        return cls.ThreadInfo(
            thread_offset,
            owner_proc_pid,
            thread_tid,
            thread_start_addr,
            start_path,
            thread_win32start_addr,
            win32start_path,
            thread_create_time,
            thread_exit_time,
        )

    def _generator(self, filter_func: Callable) -> Iterator[Tuple[int, Tuple]]:
        kernel_name = self.config["kernel"]

        vads_cache: Dict[int, pe_symbols.ranges_type] = {}

        for ethread in self.implementation(self.context, kernel_name):
            info = self.gather_thread_info(ethread, vads_cache)

            if info:
                yield (
                    0,
                    (
                        format_hints.Hex(info.offset),
                        info.pid,
                        info.tid,
                        format_hints.Hex(info.start_addr),
                        info.start_path or renderers.NotAvailableValue(),
                        format_hints.Hex(info.win32_start_addr),
                        info.win32_start_path or renderers.NotAvailableValue(),
                        info.create_time,
                        info.exit_time,
                    ),
                )

    def generate_timeline(self):
        filt_func = self.filter_func(self.config)

        for row in self._generator(filt_func):
            _depth, row_data = row
            row_dict = {}
            (
                row_dict["Offset"],
                row_dict["PID"],
                row_dict["TID"],
                row_dict["StartAddress"],
                row_dict["StartPath"],
                row_dict["Win32StartAddress"],
                row_dict["Win32StartPath"],
                row_dict["CreateTime"],
                row_dict["ExitTime"],
            ) = row_data

            # Skip threads with no creation time
            # - mainly system process threads
            if not isinstance(row_dict["CreateTime"], datetime.datetime):
                continue
            description = f"Thread: Tid {row_dict['TID']} in Pid {row_dict['PID']} (Offset {row_dict['Offset']})"

            # yield created time, and if there is exit time, yield it too.
            yield (description, timeliner.TimeLinerType.CREATED, row_dict["CreateTime"])
            if isinstance(row_dict["ExitTime"], datetime.datetime):
                yield (
                    description,
                    timeliner.TimeLinerType.MODIFIED,
                    row_dict["ExitTime"],
                )

    @classmethod
    def filter_func(cls, config: interfaces.configuration.HierarchicalDict) -> Callable:
        """Returns a function that can filter this plugin's implementation method based on the config"""
        return lambda x: False

    def run(self):
        filt_func = self.filter_func(self.config)

        return renderers.TreeGrid(
            [
                ("Offset", format_hints.Hex),
                ("PID", int),
                ("TID", int),
                ("StartAddress", format_hints.Hex),
                ("StartPath", str),
                ("Win32StartAddress", format_hints.Hex),
                ("Win32StartPath", str),
                ("CreateTime", datetime.datetime),
                ("ExitTime", datetime.datetime),
            ],
            self._generator(filt_func),
        )
