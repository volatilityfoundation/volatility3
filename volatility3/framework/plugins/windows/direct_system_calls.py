# This file is Copyright 2025 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
import logging
from volatility3.framework import interfaces, deprecation
from collections import namedtuple
from volatility3.plugins.windows.malware import direct_system_calls

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


class DirectSystemCalls(
    interfaces.plugins.PluginInterface,
    deprecation.PluginRenameClass,
    replacement_class=direct_system_calls.DirectSystemCalls,
    removal_date="2026-06-07",
):
    """Detects the Direct System Call technique used to bypass EDRs (deprecated)."""

    _required_framework_version = (2, 4, 0)

    # 2.0.0 - changes signature of `get_tasks_to_scan`
    _version = (2, 0, 0)

    # DLLs that are expected to host system call invocations
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
