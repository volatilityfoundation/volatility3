# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

import logging
import capstone
from collections import namedtuple
from typing import List, Tuple, Optional, Generator, Callable

from volatility3.framework.objects import utility
from volatility3.framework import interfaces, renderers, symbols, exceptions
from volatility3.framework.configuration import requirements
from volatility3.plugins import yarascan
from volatility3.framework.renderers import format_hints
from volatility3.plugins.windows import pslist

vollog = logging.getLogger(__name__)


# Full details on the techniques used in these plugins to detect EDR-evading malware
# can be found in our 20 page whitepaper submitted to DEFCON along with the presentation
# https://www.volexity.com/wp-content/uploads/2024/08/Defcon24_EDR_Evasion_Detection_White-Paper_Andrew-Case.pdf

syscall_finder_type = namedtuple(
    "syscall_finder_type",
    [
        "get_syscall_target_address",
        "wants_syscall_inst",
        "rule_str",
        "invalid_ops",
        "termination_ops",
    ],
)

syscall_finder_type.__doc__ = """
This type to used to specify how malicious system call invocations should be found.

`get_syscall_target_address` is optionally used to extract the address containing the malicious 'syscall' instruction
`wants_syscall_inst` whether or not this method expects the 'syscall' instrunction directly within the malicious code block
`rule` the opcode string to search for the malicious syscall instructions
`invalid_ops` instructions that only appear in invalid code blocks. Stops processing of the code block when encountered.
`termination_ops` instructions that are expected to be present in the code block and that stop processing
"""


class DirectSystemCalls(interfaces.plugins.PluginInterface):
    """Detects the Direct System Call technique used to bypass EDRs"""

    _required_framework_version = (2, 4, 0)
    _version = (1, 0, 0)

    valid_syscall_handlers = ("ntdll.dll", "win32u.dll")

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.syscall_finder = syscall_finder_type(
            # for direct system calls, we find the `syscall` instruction directly, so we already know the address
            None,
            # yes, we want the syscall instruction present as it is what this technique looks for
            True,
            # regex to find "\x0f\x05" (syscall) followed later by "\xc3" (ret)
            # we allow spacing in between to break naive anti-analysis forms (e.g., TarTarus Gate)
            # Standard techniques, such as HellsGate, look like:
            # mov r10, rcx
            # mov eax, <system call number>
            # syscall
            # ret
            "/\\x0f\\x05[^\\xc3]{,24}\\xc3/",
            # any of these will not be in a workable, malicious direct system call block
            ["jmp", "call", "leave", "int3"],
            # the expected form is to end with a "ret" back to the calling code
            ["ret"],
        )

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        # create a list of requirements for vadyarascan
        vadyarascan_requirements = [
            requirements.ModuleRequirement(
                name="kernel",
                description="Windows kernel",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.PluginRequirement(
                name="pslist", plugin=pslist.PsList, version=(2, 0, 0)
            ),
            requirements.VersionRequirement(
                name="yarascanner", component=yarascan.YaraScanner, version=(2, 1, 0)
            ),
            requirements.PluginRequirement(
                name="yarascan", plugin=yarascan.YaraScan, version=(2, 0, 0)
            ),
        ]

        # get base yarascan requirements for command line options
        yarascan_requirements = yarascan.YaraScan.get_yarascan_option_requirements()

        # return the combined requirements
        return yarascan_requirements + vadyarascan_requirements

    @staticmethod
    def _is_syscall_block(
        disasm_func: Callable,
        syscall_finder: syscall_finder_type,
        data: bytes,
        address: int,
    ) -> Optional[Tuple[str, capstone._cs_insn]]:
        """
        Determines if the bytes starting at `data` represent a valid syscall instrunction invocation block

        To maliciously invoke the system call instruction, malware must do each of the following:

        1) update RAX to the system call number
        2) update R10 to the first parameter
        3) hit the 'termination' instrunction set in `syscall_finder_type`

        We also track whether the 'syscall' instruction was encountered while parsing

        This function is reusable for every technique we found and studied during the DEFCON research timeframe

        Args:
            disasm_func: capstone disassembly function gathered from `get_disasm_function`
            syscall_finder: the method and constraints on the malicious system call blocks that the calling plugin knows how to find
            data: the bytes from memory to search for malicious syscall invocations
            address: the address from where `data` came from in the particular process
        Returns:
            Optional[Tuple[str, capstone._cs_insn]]: For valid blocks, the disassembled bytes in string from and the last (termination) instruction
        """
        found_movr10 = False
        found_movreax = False
        found_syscall = False
        found_end = False
        end_inst = None

        disasm_bytes = ""

        for inst in disasm_func(data, address):
            disasm_bytes += f"{inst.address:#x}: {inst.mnemonic} {inst.op_str}; "

            # an instruction of all 0x00 opcodes
            if inst.opcode.count(0) == len(inst.opcode):
                break

            op = inst.mnemonic

            # invalid op, bail
            if op in syscall_finder.invalid_ops:
                break

            # found the end instruction wanted by the caller
            elif op in syscall_finder.termination_ops:
                found_end = True
                end_inst = inst
                break

            # track this no matter what to make code more re-usable
            elif op == "syscall":
                found_syscall = True

                # if we hit a 'syscall' but RAX or R10 haven't been touched
                # then we are in an invalid path, so bail
                if not syscall_finder.wants_syscall_inst or (
                    not (found_movr10 and found_movreax)
                ):
                    break

            else:
                # attempt to see if any other instruction type wrote to registers
                try:
                    _, regs_written = inst.regs_access()
                except capstone.CsError:
                    continue

                if regs_written:
                    for r in regs_written:
                        # track writes to eax/rax or R10
                        reg = inst.reg_name(r)
                        if reg in ["eax", "rax"]:
                            found_movreax = True

                        elif reg == "r10":
                            found_movr10 = True

        # if any of these are missing, the block is invalid regardless of
        # the technique we are trying to detect now or in the future
        if not (found_movr10 and found_movreax and found_end):
            return None

        # if the finder requires a 'syscall' instruction then bail now if we didn't find one
        if syscall_finder.wants_syscall_inst and not found_syscall:
            return None

        return disasm_bytes, end_inst

    @staticmethod
    def get_disasm_function(architecture: str) -> Callable:
        """
        Returns the disassembly handler for the given architecture
        .detail is used to get full instruction information

        Args:
            architecture: the name of the architecture for the process being disassembled
        Returns:
            The disasm function from capstone for the given architecture
        """
        disasm_types = {
            "intel": capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32),
            "intel64": capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64),
        }

        disasm_type = disasm_types[architecture]
        disasm_type.detail = True
        return disasm_type.disasm

    @classmethod
    def _is_valid_syscall(
        cls,
        syscall_finder: syscall_finder_type,
        proc_layer: interfaces.layers.DataLayerInterface,
        architecture: str,
        vads: List[Tuple[int, int, str]],
        address: int,
    ) -> Optional[Tuple[int, str]]:
        """
        Args:
            syscall_finder:
            proc_layer: the memory layer of the process being scanned
            architecture: the name of the architecture for the process being disassembled
            vads: the ranges of this process under 10MB
            address: the starting address to check for malicious syscall code blocks

        Returns:
            Optional[Tuple[int, str]]: For valid code blocks, the starting address of the block and the disassembly string
        """
        # the number bytes behind the yara rule hit to scan
        behind = 32

        address = address - behind

        try:
            data = proc_layer.read(address, behind * 2)
        except exceptions.InvalidAddressException:
            return None

        disasm_func = cls.get_disasm_function(architecture)

        # since Intel does not have fixed-size instructions, we have to scan
        # each byte offset and re-disassemble the remaining block
        for offset in range(behind):
            # if this looks like a system call back (r10, rax, ret/jmp)
            syscall_info = cls._is_syscall_block(
                disasm_func, syscall_finder, data[offset:], address + offset
            )
            if syscall_info:
                disasm_bytes, end_inst = syscall_info

                # if we can recover (and require) a target address for this malware technique
                if syscall_finder.get_syscall_target_address:
                    target_address = syscall_finder.get_syscall_target_address(
                        proc_layer, end_inst
                    )

                    # could not determine the address -> invalid basic block
                    if not target_address:
                        continue

                    # we only care about calls to system call DLLs
                    path = cls._get_range_path(vads, target_address)
                    if not isinstance(path, str) or not path.lower().endswith(
                        cls.valid_syscall_handlers
                    ):
                        continue

                # return the address and disassembly string if all checks pass
                return address + offset, disasm_bytes

        return None

    @staticmethod
    def _get_vad_maps(
        task: interfaces.objects.ObjectInterface,
    ) -> List[Tuple[int, int, str]]:
        """Creates a map of start/end addresses within a virtual address
        descriptor tree.

        Args:
            task: The EPROCESS object of which to traverse the vad tree

        Returns:
            An iterable of tuples containing start and end addresses for each descriptor
        """
        vads: List[Tuple[int, int, str]] = []

        # scan regions under 10MB
        scan_max = 10 * 1000 * 1000

        vad_root = task.get_vad_root()

        for vad in vad_root.traverse():
            if vad.get_size() < scan_max:
                vads.append((vad.get_start(), vad.get_size(), vad.get_file_name()))

        return vads

    @staticmethod
    def _get_range_path(ranges: List[Tuple[int, int, str]], address: int) -> Optional[str]:
        """
        Returns the path for the range holding `address`, if found

        Args:
            ranges: VADs collected from `_get_vad_maps`
            address: the address to find
        Returns:
            The path holding the address, if any
        """
        for start, size, path in ranges:
            if start <= address < start + size:
                return path

        return None

    @classmethod
    def _get_tasks_to_scan(
        cls,
        context: interfaces.context.ContextInterface,
        layer_name: str,
        symbol_table_name: str,
    ) -> Generator[
        Tuple[interfaces.objects.ObjectInterface, str, str, str], None, None
    ]:
        """
        Gathers active processes with the extra information needed
        to detect malicious syscall instructions

        Returns:
            Generator of the process object, name, memory layer, and architecture
        """

        # gather active processes
        filter_func = pslist.PsList.create_active_process_filter()

        is_32bit_arch = not symbols.symbol_table_is_64bit(context, symbol_table_name)

        for proc in pslist.PsList.list_processes(
            context=context,
            layer_name=layer_name,
            symbol_table=symbol_table_name,
            filter_func=filter_func,
        ):
            proc_name = utility.array_to_string(proc.ImageFileName)

            # skip Defender
            if proc_name in ["MsMpEng.exe"]:
                continue

            try:
                proc_layer_name = proc.add_process_layer()
            except exceptions.InvalidAddressException:
                continue

            if is_32bit_arch or proc.get_is_wow64():
                architecture = "intel"
            else:
                architecture = "intel64"

            yield proc, proc_name, proc_layer_name, architecture

    @classmethod
    def _get_rule_hits(
        cls,
        context: interfaces.objects.ObjectInterface,
        proc_layer: interfaces.layers.DataLayerInterface,
        vads: List[Tuple[int, int, str]],
        pattern: str,
    ) -> Generator[Tuple[int, Optional[str]], None, None]:
        """
        Runs the given opcode rule through Yara and returns the address and file path of hits

        Args:
            context:
            proc_layer: the layer to scan
            vads: the ranges inside of the process being scanned
            pattern: the opcodes rule from the plugin to detect a particular EDR-bypass technique

        Returns:
            Generator of the address and file path of hits
        """
        sections = [(vad[0], vad[1]) for vad in vads]

        rule = yarascan.YaraScanner.get_rule(pattern)

        for hit in proc_layer.scan(
            context=context,
            scanner=yarascan.YaraScanner(rules=rule),
            sections=sections,
        ):
            address = hit[0]

            path = cls._get_range_path(vads, address)

            # ignore hits in the system call DLLs
            if isinstance(path, str) and path.lower().endswith(
                cls.valid_syscall_handlers
            ):
                continue

            yield address, path

    def _generator(self) -> Generator[Tuple[int, Tuple[str, int, Optional[str], int, str]], None, None]:
        kernel = self.context.modules[self.config["kernel"]]

        for proc, proc_name, proc_layer_name, architecture in self._get_tasks_to_scan(
            self.context, kernel.layer_name, kernel.symbol_table_name
        ):
            proc_layer = self.context.layers[proc_layer_name]

            vads = self._get_vad_maps(proc)

            # for each valid process, look for malicious syscall invocations
            for address, vad_path in self._get_rule_hits(
                self.context, proc_layer, vads, self.syscall_finder.rule_str
            ):
                syscall_info = self._is_valid_syscall(
                    self.syscall_finder, proc_layer, architecture, vads, address
                )
                if not syscall_info:
                    continue

                address, disasm_bytes = syscall_info

                yield 0, (
                    proc_name,
                    proc.UniqueProcessId,
                    vad_path,
                    format_hints.Hex(address),
                    disasm_bytes,
                )

    def run(self) -> renderers.TreeGrid:
        return renderers.TreeGrid(
            [
                ("Process", str),
                ("PID", int),
                ("Range", str),
                ("Address", format_hints.Hex),
                ("Disasm", str),
            ],
            self._generator(),
        )
