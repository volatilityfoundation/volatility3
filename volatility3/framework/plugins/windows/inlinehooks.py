import logging
from typing import List, Tuple, Iterable, Optional
from enum import Enum
import time

from volatility3.framework import interfaces, renderers, exceptions
from volatility3.framework.configuration import requirements
from volatility3.framework.renderers import format_hints
from volatility3.plugins.windows import pslist, pe_symbols, modules

vollog = logging.getLogger(__name__)


class HookType(Enum):
    """Enum defining different types of API hooks"""

    INLINE = "Inline Hook"
    IAT = "Import Address Table Hook"
    EAT = "Export Address Table Hook"


# https://github.com/SolitudePy/Inline-Hooks
class InlineHooks(interfaces.plugins.PluginInterface):
    """Detect various types of Inline hooks in process memory"""

    _version = (1, 0, 0)
    _required_framework_version = (2, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
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
                name="modules",
                component=modules.Modules,
                version=(3, 0, 0),  # Updated from 2.0.0 to 3.0.0
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

    def _count_until_padding(self, data: bytes) -> int:
        # Check for padding sequences
        for i in range(len(data)):
            # Double int3 (CC CC)
            if i + 1 < len(data) and data[i] == 0xCC and data[i + 1] == 0xCC:
                return i
            # 11-byte NOP (66 66 66 0f 1f 84 00 00 00 00 00)
            if (
                i + 11 <= len(data)
                and data[i : i + 11] == b"\x66\x66\x66\x0f\x1f\x84\x00\x00\x00\x00\x00"
            ):
                return i
            # 2-byte NOP (66 66)
            if i + 2 <= len(data) and data[i : i + 2] == b"\x66\x66":
                return i
        return len(data)

    def check_inline_hook(
        self, data: bytes, addr: int = 0
    ) -> Optional[Tuple[bytes, str]]:
        """Check for inline API hooks by analyzing instructions"""

        # Constants for minimum function sizes
        # This is important to avoid false positives on stub functions
        MIN_FUNC_SIZE_FOR_JMP = 2
        MIN_FUNC_SIZE_FOR_RET = 2
        MIN_FUNC_SIZE_FOR_CALL = 2

        if len(data) < 1:
            return None

        try:
            import capstone
        except ImportError:
            vollog.warning(
                "Capstone not available - inline hook detection will be limited"
            )
            return None

        data = data[: self._count_until_padding(data)]

        try:
            # Set up disassembler
            md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
            md.detail = True

            disasm = list(md.disasm(data, addr))
            func_insn_count = len(disasm)

            if func_insn_count == 0:
                return None

            # Check for NOP sled
            if (
                func_insn_count >= 3
                and disasm[0].mnemonic == "nop"
                and disasm[1].mnemonic == "nop"
                and disasm[2].mnemonic == "nop"
            ):
                return (data, "NOP sled")

            # Check for Early RET
            if func_insn_count >= MIN_FUNC_SIZE_FOR_RET:
                if (
                    (disasm[0].id == capstone.x86.X86_INS_RET)
                    or (
                        func_insn_count >= 2
                        and disasm[0].mnemonic == "push"
                        and disasm[1].id == capstone.x86.X86_INS_RET
                    )
                    or (
                        func_insn_count >= 2
                        and disasm[0].mnemonic == "call"
                        and disasm[1].id == capstone.x86.X86_INS_RET
                    )
                    or (
                        func_insn_count >= 2
                        and disasm[0].mnemonic == "jmp"
                        and disasm[1].id == capstone.x86.X86_INS_RET
                    )
                ):
                    return (data, "Early RET")

            # Check for JMP relative hooks
            if disasm[0].bytes[0] == 0xE9 and func_insn_count >= MIN_FUNC_SIZE_FOR_JMP:
                return (data, "JMP relative")

            # Check for Early CALL hooks
            if (
                func_insn_count >= MIN_FUNC_SIZE_FOR_CALL
                and disasm[0].mnemonic == "call"
            ):
                return (data, "Early CALL")

        except Exception as e:
            vollog.debug(f"Error during disassembly at {addr:#x}: {e}")

        return None

    """def _check_iat_hooks_for_process(self, proc) -> List[Tuple[str, int, str]]:
        #Check for Import Address Table hooks for an entire process using the existing IAT plugin
        hooked_imports = []

        try:
            # Create IAT plugin instance to reuse its functionality
            iat_plugin = iat.IAT(self.context, self.config_path)

            # Get IAT entries for this specific process
            iat_entries = list(iat_plugin._generator([proc]))
            # print(f"Found {len(iat_entries)} IAT entries for process {proc.UniqueProcessId}")  # Commented out debug print

            # Get process layer for module bounds checking
            proc_layer_name = proc.add_process_layer()
            proc_layer = self.context.layers[proc_layer_name]

            # Build a map of loaded modules and their bounds
            module_bounds = {}
            for mod in proc.load_order_modules():
                try:
                    module_name = mod.BaseDllName.get_string().lower()
                    module_bounds[module_name] = (mod.DllBase, mod.DllBase + mod.SizeOfImage)
                except:
                    continue

            # Check each IAT entry for suspicious redirections
            for _, (pid, proc_name, dll_name, bound, function_name, function_address) in iat_entries:
                try:
                    if function_address:
                        addr = int(function_address) if hasattr(function_address, '__int__') else function_address

                        # Check if this address is within the expected module bounds
                        is_within_bounds = False

                        # Check against all loaded modules (not just the declaring DLL)
                        for mod_name, (mod_start, mod_end) in module_bounds.items():
                            if mod_start <= addr < mod_end:
                                is_within_bounds = True
                                break

                        if not is_within_bounds:
                            hooked_imports.append((
                                f"{dll_name}::{function_name}",
                                addr,
                                "IAT entry points outside any loaded module (hooked)"
                            ))

                except (exceptions.InvalidAddressException, ValueError, TypeError):
                    continue

        except Exception as e:
            vollog.debug(f"Error in IAT hook detection: {e}")

        return hooked_imports"""

    """def _check_eat_hook(self, proc_layer, module, export_dir) -> List[Tuple[str, int, str]]:
        #Check for Export Address Table hooks
        hooked_exports = []

        try:
            module_start = module.DllBase
            module_end = module.DllBase + module.SizeOfImage

            # Walk the EAT
            for export in export_dir.entries():
                try:
                    expected_rva = export.rva
                    # Read pointer value properly using struct.unpack
                    pointer_size = proc_layer.context.symbol_space.get_type("pointer").size
                    pointer_data = proc_layer.read(module.DllBase + expected_rva, pointer_size)
                    actual_addr = struct.unpack("<Q" if pointer_size == 8 else "<I", pointer_data)[0]

                    # Check if address points outside the module
                    if actual_addr and not (module_start <= actual_addr < module_end):
                        hooked_exports.append((
                            export.name or "",
                            actual_addr,
                            "EAT entry redirected"
                        ))
                except exceptions.InvalidAddressException:
                    continue

        except exceptions.InvalidAddressException:
            pass

        return hooked_exports"""

    def _scan_process_modules(
        self, proc
    ) -> Iterable[Tuple[HookType, str, int, str, str, bytes]]:
        """Scan modules in a process for different types of API hooks"""
        try:
            proc_layer_name = proc.add_process_layer()
            proc_layer = self.context.layers[proc_layer_name]
        except Exception as e:
            vollog.debug(
                f"Error getting process layer for PID {proc.UniqueProcessId}: {e}"
            )
            return

        # Scan each loaded module
        for mod in proc.load_order_modules():
            try:
                module_name = mod.BaseDllName.get_string()
            except exceptions.InvalidAddressException:
                vollog.debug(f"Invalid module name for {mod.DllBase:#x}")
                continue

            # Get exported symbols
            symbol_table_name = mod.get_symbol_table_name()

            if not symbol_table_name:
                continue

            try:
                # Get symbol finders for this module
                export_finders = list(
                    pe_symbols.PESymbols._find_symbols_through_exports(
                        self.context,
                        self.config_path,
                        [(proc_layer_name, mod.DllBase, mod.SizeOfImage)],
                        module_name.lower(),
                    )
                )

                if not export_finders:
                    continue

                # Check exports across all export finders
                for finder in export_finders:
                    for export in finder._symbol_module:
                        try:
                            export_name = finder._get_name(export)
                            if not export_name:
                                continue

                            export_addr = finder._module_start + export.address
                            if not export_addr:
                                continue

                            try:
                                vollog.debug(
                                    f"Analyzing {module_name}::{export_name} at {export_addr:#x}"
                                )

                                # Read data for analysis
                                data = proc_layer.read(export_addr, 24)

                                disasm = renderers.Disassembly(data, export_addr)

                                inline_hook_check = self.check_inline_hook(
                                    data=data, addr=export_addr
                                )
                                if inline_hook_check:
                                    vollog.info(
                                        f"Inline hook detected in {module_name}::{export_name} at {export_addr:#x}: {inline_hook_check[1]}"
                                    )
                                    yield (
                                        HookType.INLINE,
                                        module_name,
                                        export_addr,
                                        export_name,
                                        inline_hook_check[1],
                                        inline_hook_check[0],
                                        disasm,
                                    )

                            except exceptions.InvalidAddressException:
                                vollog.debug(
                                    f"Invalid address for {module_name}::{export_name} at {export_addr:#x}"
                                )
                                continue

                        except Exception as e:
                            vollog.debug(
                                f"Error processing export {export_name if 'export_name' in locals() else 'unknown'}: {e}"
                            )
                            continue

            except Exception as e:
                vollog.debug(f"Error processing module {module_name}: {e}")
                continue

    def _generator(self):
        start = time.time()
        filter_func = pslist.PsList.create_pid_filter(self.config.get("pid", None))

        hook_count = 0

        for proc in pslist.PsList.list_processes(
            context=self.context,
            kernel_module_name=self.config["kernel"],
            filter_func=filter_func,
        ):
            proc_id = proc.UniqueProcessId
            proc_name = proc.ImageFileName.cast(
                "string", max_length=proc.ImageFileName.vol.count, errors="replace"
            )

            # Check for all hook types
            for (
                hook_type,
                module_name,
                hook_addr,
                function_name,
                hook_info,
                hook_data,
                disasm,
            ) in self._scan_process_modules(proc):
                hook_count += 1
                yield (
                    0,
                    (
                        proc_id,
                        proc_name,
                        hook_type.value,
                        module_name,
                        format_hints.Hex(hook_addr),
                        function_name,
                        hook_info,
                        (
                            format_hints.HexBytes(hook_data)
                            if hook_data
                            else format_hints.HexBytes(b"")
                        ),
                        disasm,
                    ),
                )

        end = time.time()
        vollog.info(
            f"InlineHooks plugin completed in {end - start:.2f} seconds, found {hook_count} hooks"
        )

    def run(self):
        return renderers.TreeGrid(
            [
                ("PID", int),
                ("Process", str),
                ("Hook Type", str),
                ("Module", str),
                ("Hook Address", format_hints.Hex),
                ("Function", str),
                ("Hook Info", str),
                ("Hook Hexdump", format_hints.HexBytes),
                ("Disasm", renderers.Disassembly),
            ],
            self._generator(),
        )
