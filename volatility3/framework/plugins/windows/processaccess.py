# This file is Copyright 2026 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

import logging
from typing import List

from volatility3.framework import constants, exceptions, interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.objects import utility
from volatility3.framework.renderers import format_hints
from volatility3.plugins.windows import handles, pslist

vollog = logging.getLogger(__name__)

_PROCESS_TERMINATE = 0x0001
_PROCESS_CREATE_THREAD = 0x0002
_PROCESS_VM_OPERATION = 0x0008
_PROCESS_VM_READ = 0x0010
_PROCESS_VM_WRITE = 0x0020
_PROCESS_DUP_HANDLE = 0x0040
_PROCESS_CREATE_PROCESS = 0x0080
_PROCESS_SUSPEND_RESUME = 0x0800

_PROCESS_RIGHTS = (
    (_PROCESS_TERMINATE, "PROCESS_TERMINATE"),
    (_PROCESS_CREATE_THREAD, "PROCESS_CREATE_THREAD"),
    (0x0004, "PROCESS_SET_SESSIONID"),
    (_PROCESS_VM_OPERATION, "PROCESS_VM_OPERATION"),
    (_PROCESS_VM_READ, "PROCESS_VM_READ"),
    (_PROCESS_VM_WRITE, "PROCESS_VM_WRITE"),
    (_PROCESS_DUP_HANDLE, "PROCESS_DUP_HANDLE"),
    (_PROCESS_CREATE_PROCESS, "PROCESS_CREATE_PROCESS"),
    (0x0100, "PROCESS_SET_QUOTA"),
    (0x0200, "PROCESS_SET_INFORMATION"),
    (0x0400, "PROCESS_QUERY_INFORMATION"),
    (_PROCESS_SUSPEND_RESUME, "PROCESS_SUSPEND_RESUME"),
    (0x1000, "PROCESS_QUERY_LIMITED_INFORMATION"),
    (0x00010000, "DELETE"),
    (0x00020000, "READ_CONTROL"),
    (0x00040000, "WRITE_DAC"),
    (0x00080000, "WRITE_OWNER"),
    (0x00100000, "SYNCHRONIZE"),
    (0x01000000, "ACCESS_SYSTEM_SECURITY"),
    (0x02000000, "MAXIMUM_ALLOWED"),
)

_KNOWN_ACCESS_MASK = 0
for _right, _name in _PROCESS_RIGHTS:
    _KNOWN_ACCESS_MASK |= _right

_MEMORY_ACCESS_MASK = (
    _PROCESS_CREATE_THREAD
    | _PROCESS_VM_OPERATION
    | _PROCESS_VM_READ
    | _PROCESS_VM_WRITE
    | _PROCESS_DUP_HANDLE
    | _PROCESS_SUSPEND_RESUME
)

_MEMORY_MODIFICATION_MASK = _PROCESS_VM_OPERATION | _PROCESS_VM_WRITE
_THREAD_MEMORY_MODIFICATION_MASK = (
    _PROCESS_CREATE_THREAD | _PROCESS_VM_OPERATION | _PROCESS_VM_WRITE
)
_PROCESS_CONTROL_MASK = _PROCESS_TERMINATE | _PROCESS_SUSPEND_RESUME


class ProcessAccess(interfaces.plugins.PluginInterface):
    """Lists process-to-process handles and summarizes their access capabilities."""

    _required_framework_version = (2, 0, 0)
    _version = (1, 1, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Windows kernel",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.ListRequirement(
                name="pid",
                description="Process IDs to include as handle owners",
                element_type=int,
                optional=True,
            ),
            requirements.ListRequirement(
                name="target_pid",
                description="Target process IDs to include",
                element_type=int,
                optional=True,
            ),
            requirements.BooleanRequirement(
                name="memory_access",
                description="Only show handles with memory-manipulation-related rights",
                default=False,
                optional=True,
            ),
            requirements.VersionRequirement(
                name="pslist", component=pslist.PsList, version=(3, 0, 0)
            ),
            requirements.VersionRequirement(
                name="handles", component=handles.Handles, version=(4, 0, 0)
            ),
        ]

    @classmethod
    def decode_access_mask(cls, access_mask: int) -> str:
        """Translates a process GrantedAccess mask into named access rights."""
        rights = [name for bit, name in _PROCESS_RIGHTS if access_mask & bit]
        unknown_bits = access_mask & ~_KNOWN_ACCESS_MASK
        if unknown_bits:
            rights.append(f"UNKNOWN(0x{unknown_bits:x})")
        return ",".join(rights) if rights else "NONE"

    @classmethod
    def categorize_access(cls, access_mask: int) -> str:
        """Summarizes process access rights into investigation-oriented capabilities."""
        categories = []

        if access_mask & _PROCESS_VM_READ:
            categories.append("MEMORY_READ")

        if (
            access_mask & _THREAD_MEMORY_MODIFICATION_MASK
            == _THREAD_MEMORY_MODIFICATION_MASK
        ):
            categories.append("THREAD_AND_MEMORY_MODIFICATION")
        elif access_mask & _MEMORY_MODIFICATION_MASK == _MEMORY_MODIFICATION_MASK:
            categories.append("MEMORY_MODIFICATION")
        else:
            if access_mask & _PROCESS_VM_WRITE:
                categories.append("MEMORY_WRITE")
            if access_mask & _PROCESS_VM_OPERATION:
                categories.append("ADDRESS_SPACE_OPERATION")
            if access_mask & _PROCESS_CREATE_THREAD:
                categories.append("THREAD_CREATION")

        if access_mask & _PROCESS_DUP_HANDLE:
            categories.append("HANDLE_DUPLICATION")

        if access_mask & _PROCESS_CREATE_PROCESS:
            categories.append("PROCESS_CREATION")

        if access_mask & _PROCESS_CONTROL_MASK:
            categories.append("PROCESS_CONTROL")

        if categories:
            return ",".join(categories)
        return "OTHER_PROCESS_ACCESS" if access_mask else "NONE"

    @classmethod
    def has_memory_related_access(cls, access_mask: int) -> bool:
        """Checks whether a process handle grants memory-related access rights."""
        return bool(access_mask & _MEMORY_ACCESS_MASK)

    def _generator(self, procs):
        type_map = handles.Handles.get_type_map(
            context=self.context, kernel_module_name=self.config["kernel"]
        )
        cookie = handles.Handles.find_cookie(
            context=self.context, kernel_module_name=self.config["kernel"]
        )

        target_pid_filter = set(self.config.get("target_pid", []) or [])
        memory_access_only = self.config.get("memory_access", False)

        for proc in procs:
            try:
                object_table = proc.ObjectTable
                source_pid = int(proc.UniqueProcessId)
                source_name = utility.array_to_string(proc.ImageFileName)
            except exceptions.InvalidAddressException:
                vollog.log(
                    constants.LOGLEVEL_VVV,
                    f"Cannot access source process at {proc.vol.offset:#x}",
                )
                continue

            for entry in handles.Handles.handles(
                context=self.context,
                kernel_module_name=self.config["kernel"],
                handle_table=object_table,
            ):
                try:
                    if entry.get_object_type(type_map, cookie) != "Process":
                        continue

                    target = entry.Body.cast("_EPROCESS")
                    target_pid = int(target.UniqueProcessId)
                    if target_pid_filter and target_pid not in target_pid_filter:
                        continue

                    granted_access = int(entry.GrantedAccess)
                    if memory_access_only and not self.has_memory_related_access(
                        granted_access
                    ):
                        continue

                    target_name = utility.array_to_string(target.ImageFileName)
                    yield (
                        0,
                        (
                            source_pid,
                            source_name,
                            target_pid,
                            target_name,
                            format_hints.Hex(int(entry.HandleValue)),
                            format_hints.Hex(granted_access),
                            self.decode_access_mask(granted_access),
                            self.categorize_access(granted_access),
                        ),
                    )
                except exceptions.InvalidAddressException:
                    vollog.log(
                        constants.LOGLEVEL_VVV,
                        f"Invalid process handle encountered in PID {source_pid}",
                    )
                    continue

    def run(self):
        source_filter = pslist.PsList.create_pid_filter(self.config.get("pid", None))
        procs = pslist.PsList.list_processes(
            context=self.context,
            kernel_module_name=self.config["kernel"],
            filter_func=source_filter,
        )

        return renderers.TreeGrid(
            [
                ("SourcePID", int),
                ("SourceProcess", str),
                ("TargetPID", int),
                ("TargetProcess", str),
                ("HandleValue", format_hints.Hex),
                ("GrantedAccess", format_hints.Hex),
                ("Rights", str),
                ("AccessCategory", str),
            ],
            self._generator(procs),
        )
