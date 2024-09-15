# This file is Copyright 2024 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0

import logging

from typing import Dict, Tuple, List, Generator

from volatility3.framework import interfaces, exceptions
from volatility3.framework import renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.objects import utility
from volatility3.plugins.windows import pslist, pe_symbols

vollog = logging.getLogger(__name__)


class unhooked_system_calls(interfaces.plugins.PluginInterface):
    """Looks for signs of Skeleton Key malware"""

    _required_framework_version = (2, 4, 0)

    system_calls = {
        "ntdll.dll": {
            pe_symbols.wanted_names_identifier: [
                "NtCreateThread",
                "NtProtectVirtualMemory",
                "NtReadVirtualMemory",
                "NtOpenProcess",
                "NtWriteFile",
                "NtQueryVirtualMemory",
                "NtAllocateVirtualMemory",
                "NtWorkerFactoryWorkerReady",
                "NtAcceptConnectPort",
                "NtAddDriverEntry",
                "NtAdjustPrivilegesToken",
                "NtAlpcCreatePort",
                "NtClose",
                "NtCreateFile",
                "NtCreateMutant",
                "NtOpenFile",
                "NtOpenIoCompletion",
                "NtOpenJobObject",
                "NtOpenKey",
                "NtOpenKeyEx",
                "NtOpenThread",
                "NtOpenThreadToken",
                "NtOpenThreadTokenEx",
                "NtWriteVirtualMemory",
                "NtTraceEvent",
                "NtTranslateFilePath",
                "NtUmsThreadYield",
                "NtUnloadDriver",
                "NtUnloadKey",
                "NtUnloadKey2",
                "NtUnloadKeyEx",
                "NtCreateKey",
                "NtCreateSection",
                "NtDeleteKey",
                "NtDeleteValueKey",
                "NtDuplicateObject",
                "NtQueryValueKey",
                "NtReplaceKey",
                "NtRequestWaitReplyPort",
                "NtRestoreKey",
                "NtSetContextThread",
                "NtSetSecurityObject",
                "NtSetValueKey",
                "NtSystemDebugControl",
                "NtTerminateProcess",
            ]
        }
    }

    # This data structure is used to track unique implementations of functions across processes
    # The outer dictionary holds the module name (e.g., ntdll.dll)
    # The next dictionary holds the function names (NtTerminateProcess, NtSetValueKey, etc.) inside a module
    # The innermost dictionary holds the unique implementation (bytes) of a function across processes
    # Each implementation is tracked along with the process(es) that host it
    # For systems without malware, all functions should have the same implementation
    # When API hooking/module unhooking is done, the victim (infected) processes will have unique implementations
    _code_bytes_type = Dict[str, Dict[str, Dict[bytes, List[Tuple[int, str]]]]]

    @classmethod
    def get_requirements(cls) -> List:
        # Since we're calling the plugin, make sure we have the plugin's requirements
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Windows kernel",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.VersionRequirement(
                name="pslist", component=pslist.PsList, version=(2, 0, 0)
            ),
            requirements.PluginRequirement(
                name="pe_symbols", plugin=pe_symbols.PESymbols, version=(1, 0, 0)
            ),
        ]

    def _gather_code_bytes(
        self,
        kernel: interfaces.context.ModuleInterface,
        found_symbols: pe_symbols.found_symbols_type,
    ) -> _code_bytes_type:
        """
        Enumerates the desired DLLs and function implementations in each process
        Groups based on unique implementations of each DLLs' functions
        The purpose is to detect when a function has different implementations (code)
        in different processes.
        This very effectively detects code injection.
        """
        code_bytes: unhooked_system_calls._code_bytes_type = {}

        procs = pslist.PsList.list_processes(
            context=self.context,
            layer_name=kernel.layer_name,
            symbol_table=kernel.symbol_table_name,
        )

        for proc in procs:
            try:
                proc_id = proc.UniqueProcessId
                proc_name = utility.array_to_string(proc.ImageFileName)
                proc_layer_name = proc.add_process_layer()
            except exceptions.InvalidAddressException:
                continue

            for dll_name, functions in found_symbols.items():
                for func_name, func_addr in functions:
                    try:
                        fbytes = self.context.layers[proc_layer_name].read(
                            func_addr, 0x20
                        )
                    except exceptions.InvalidAddressException:
                        continue

                    # see the definition of _code_bytes_type for details of this data structure
                    if dll_name not in code_bytes:
                        code_bytes[dll_name] = {}

                    if func_name not in code_bytes[dll_name]:
                        code_bytes[dll_name][func_name] = {}

                    if fbytes not in code_bytes[dll_name][func_name]:
                        code_bytes[dll_name][func_name][fbytes] = []

                    code_bytes[dll_name][func_name][fbytes].append((proc_id, proc_name))

        return code_bytes

    def _generator(self) -> Generator[Tuple[int, Tuple[str, str, int]], None, None]:
        kernel = self.context.modules[self.config["kernel"]]

        found_symbols = pe_symbols.PESymbols.addresses_for_process_symbols(
            self.context,
            self.config_path,
            kernel.layer_name,
            kernel.symbol_table_name,
            unhooked_system_calls.system_calls,
        )

        # code_bytes[dll_name][func_name][func_bytes]
        code_bytes = self._gather_code_bytes(kernel, found_symbols)

        for functions in code_bytes.values():
            for func_name, cbb in functions.items():
                cb = list(cbb.values())

                # same implementation in all
                if len(cb) == 1:
                    yield 0, (func_name, "", len(cb[0]))
                else:
                    # find the processes that are hooked for reporting
                    max_idx = 0 if len(cb[0]) > len(cb[1]) else 1
                    small_idx = (~max_idx) & 1

                    ps = []

                    for pid, pname in cb[small_idx]:
                        ps.append("{:d}:{}".format(pid, pname))

                    proc_names = ", ".join(ps)

                    yield 0, (func_name, proc_names, len(cb[max_idx]))

    def run(self) -> renderers.TreeGrid:
        return renderers.TreeGrid(
            [
                ("Function", str),
                ("Distinct Implementations", str),
                ("Total Implementations", int),
            ],
            self._generator(),
        )
