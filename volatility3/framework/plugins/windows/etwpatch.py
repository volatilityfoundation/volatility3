# This file is Copyright 2025 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
import logging

from volatility3.framework import exceptions, interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.objects import utility
from volatility3.framework.renderers import format_hints
from volatility3.plugins.windows import pslist, pe_symbols

vollog = logging.getLogger(__name__)


# EtwpEventWriteFull -> https://github.com/SolitudePy/Stealthy-ETW-Patch
# CAPA rule -> https://github.com/mandiant/capa-rules/blob/master/anti-analysis/anti-av/patch-event-tracing-for-windows-function.yml
class EtwPatch(interfaces.plugins.PluginInterface):
    """Identifies ETW (Event Tracing for Windows) patching techniques used by malware to evade detection.

    This plugin examines the first opcode of key ETW functions in ntdll.dll and advapi32.dll
    to detect common ETW bypass techniques such as return pointer manipulation (RET) or function
    redirection (JMP). Attackers often patch these functions to prevent security tools from
    receiving telemetry about process execution, API calls, and other system events.
    """

    _version = (1, 0, 0)
    _required_framework_version = (2, 26, 0)

    etw_functions = {
        "ntdll.dll": {
            pe_symbols.wanted_names_identifier: [
                "EtwEventWrite",
                "EtwEventWriteFull",
                "NtTraceEvent",
                "ZwTraceEvent",
                "NtTraceControl",
                "ZwTraceControl",
                "EtwpEventWriteFull",
            ],
        },
        "advapi32.dll": {
            pe_symbols.wanted_names_identifier: ["EventWrite", "TraceEvent"],
        },
    }

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
            requirements.ListRequirement(
                name="pid",
                description="Filter on specific process IDs",
                element_type=int,
                optional=True,
            ),
        ]

    def _generator(self):
        # Get all ETW function addresses before looping through processes
        found_symbols = pe_symbols.PESymbols.addresses_for_process_symbols(
            context=self.context,
            config_path=self.config_path,
            kernel_module_name=self.config["kernel"],
            symbols=self.etw_functions,
        )

        filter_func = pslist.PsList.create_pid_filter(self.config.get("pid", None))

        for proc in pslist.PsList.list_processes(
            context=self.context,
            kernel_module_name=self.config["kernel"],
            filter_func=filter_func,
        ):
            try:
                proc_id = proc.UniqueProcessId
                proc_name = utility.array_to_string(proc.ImageFileName)
                proc_layer_name = proc.add_process_layer()
            except exceptions.InvalidAddressException:
                vollog.debug(f"Unable to create process layer for PID {proc_id}")
                continue

            # Map of opcodes to their instruction names
            opcode_map = {
                0xC3: "RET",
                0xE9: "JMP",
            }

            for dll_name, functions in found_symbols.items():
                for func_name, func_addr in functions:
                    try:
                        opcode = self.context.layers[proc_layer_name].read(
                            func_addr, 1
                        )[0]
                        if opcode in opcode_map:
                            instruction = opcode_map[opcode]
                            yield (
                                0,
                                (
                                    proc_id,
                                    proc_name,
                                    dll_name,
                                    func_name,
                                    format_hints.Hex(func_addr),
                                    f"{opcode:02x} ({instruction})",
                                ),
                            )
                    except exceptions.InvalidAddressException:
                        vollog.debug(
                            f"Invalid address when reading function {func_name} at {func_addr:#x} in process {proc_id}"
                        )

    def run(self):
        return renderers.TreeGrid(
            [
                ("PID", int),
                ("Process", str),
                ("DLL", str),
                ("Function", str),
                ("Offset", format_hints.Hex),
                ("Opcode", str),
            ],
            self._generator(),
        )
