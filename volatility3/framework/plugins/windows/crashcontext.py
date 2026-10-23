# This file is Copyright 2026 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

import logging
from typing import List

from volatility3.framework import interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.layers import crash

vollog = logging.getLogger(__name__)


class CrashContext(interfaces.plugins.PluginInterface, crash.MiniKernelDumpMixin):
    """Reports Windows mini kernel dump crash context without kernel symbols."""

    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 0)

    BUGCHECK_NAMES = {
        0x1E: "KMODE_EXCEPTION_NOT_HANDLED",
        0x3B: "SYSTEM_SERVICE_EXCEPTION",
        0x7E: "SYSTEM_THREAD_EXCEPTION_NOT_HANDLED",
        0x9F: "DRIVER_POWER_STATE_FAILURE",
        0xA: "IRQL_NOT_LESS_OR_EQUAL",
        0xD1: "DRIVER_IRQL_NOT_LESS_OR_EQUAL",
        0xEA: "THREAD_STUCK_IN_DEVICE_DRIVER",
        0xEF: "CRITICAL_PROCESS_DIED",
        0xF7: "DRIVER_OVERRAN_STACK_BUFFER",
        0x133: "DPC_WATCHDOG_VIOLATION",
        0x139: "KERNEL_SECURITY_CHECK_FAILURE",
        0x13A: "KERNEL_MODE_HEAP_CORRUPTION",
    }

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.TranslationLayerRequirement(
                name="primary",
                description="Memory layer for the kernel",
                architectures=["Intel64"],
            ),
        ]

    @staticmethod
    def _exception_code(header: interfaces.objects.ObjectInterface) -> int:
        return int(header.Exception.ExceptionCode) & 0xFFFFFFFF

    def _generator(self):
        crash_layer = self._get_crash_layer(
            self.context, self.config.get("primary", None)
        )
        if crash_layer is None:
            vollog.error("This plugin requires a Windows mini kernel crash dump")
            raise ValueError("This plugin requires a Windows mini kernel crash dump")

        header = crash_layer.get_header()
        bugcheck_code = int(header.BugCheckCode)
        bugcheck_params = [int(param) for param in header.BugCheckCodeParameter]
        bugcheck_data_offset, bugcheck_data_size = (
            crash_layer.get_mini_kernel_bugcheck_data_range()
        )

        rows = [
            ("BugCheckCode", f"{bugcheck_code:#x}"),
            (
                "BugCheckName",
                self.BUGCHECK_NAMES.get(bugcheck_code, "UNKNOWN"),
            ),
            (
                "BugCheckParameters",
                ", ".join(f"{parameter:#x}" for parameter in bugcheck_params),
            ),
            ("ExceptionCode", f"{self._exception_code(header):#x}"),
            (
                "ExceptionAddress",
                f"{int(header.Exception.ExceptionAddress):#x}",
            ),
            (
                "KdDebuggerDataBlock",
                f"{int(header.KdDebuggerDataBlock):#x}",
            ),
            (
                "PsLoadedModuleList",
                f"{int(header.PsLoadedModuleList):#x}",
            ),
            ("CapturedRangeCount", str(crash_layer.range_table_count)),
            ("ModuleCount", str(crash_layer.get_mini_kernel_module_count())),
            ("BugCheckDataOffset", f"{bugcheck_data_offset:#x}"),
            ("BugCheckDataSize", f"{bugcheck_data_size:#x}"),
        ]

        for key, value in rows:
            yield (0, (key, value))

    def run(self):
        return renderers.TreeGrid(
            [
                ("Key", str),
                ("Value", str),
            ],
            self._generator(),
        )
