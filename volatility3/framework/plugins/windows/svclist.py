# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

import logging

from typing import List, Optional, Tuple

from volatility3.framework import interfaces, exceptions, symbols
from volatility3.framework.configuration import requirements
from volatility3.framework.symbols.windows import versions
from volatility3.plugins.windows import svcscan, pslist
from volatility3.framework.layers import scanners

vollog = logging.getLogger(__name__)


class SvcList(svcscan.SvcScan):
    """Lists services contained with the services.exe doubly linked list of services"""

    _required_framework_version = (2, 0, 0)

    # 2.0.0 - service_list signature changed
    _version = (2, 0, 0)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._enumeration_method = self.service_list

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        # Since we're calling the plugin, make sure we have the plugin's requirements
        return [
            requirements.VersionRequirement(
                name="svcscan", component=svcscan.SvcScan, version=(4, 0, 0)
            ),
            requirements.VersionRequirement(
                name="pslist", component=pslist.PsList, version=(3, 0, 0)
            ),
            requirements.ModuleRequirement(
                name="kernel",
                description="Windows kernel",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.VersionRequirement(
                name="bytes_scanner",
                component=scanners.BytesScanner,
                version=(1, 0, 0),
            ),
        ]

    @classmethod
    def _get_exe_range(cls, proc) -> Optional[Tuple[int, int]]:
        """
        Returns a tuple of starting address and size of
        the VAD containing services.exe
        """

        vad_root = proc.get_vad_root()
        for vad in vad_root.traverse():
            filename = vad.get_file_name()
            if isinstance(filename, str) and filename.lower().endswith(
                "\\services.exe"
            ):
                return [(vad.get_start(), vad.get_size())]

        return None

    @classmethod
    def service_list(
        cls,
        context: interfaces.context.ContextInterface,
        kernel_module_name: str,
        service_table_name: str,
        service_binary_dll_map,
        filter_func,
    ):
        kernel = context.modules[kernel_module_name]

        if not symbols.symbol_table_is_64bit(
            context=context, symbol_table_name=kernel.symbol_table_name
        ) or not versions.is_win10_15063_or_later(
            context=context, symbol_table=kernel.symbol_table_name
        ):
            vollog.warning(
                "This plugin only supports Windows 10 version 15063+ 64bit Windows memory samples"
            )
            return

        for proc in pslist.PsList.list_processes(
            context=context,
            kernel_module_name=kernel_module_name,
            filter_func=filter_func,
        ):
            try:
                proc_layer_name = proc.add_process_layer()
            except exceptions.InvalidAddressException:
                vollog.warning(
                    f"Unable to access memory of services.exe running with PID: {proc.UniqueProcessId}"
                )
                continue

            proc_layer = context.layers[proc_layer_name]

            exe_range = cls._get_exe_range(proc)
            if not exe_range:
                vollog.warning(
                    "Could not find the application executable VAD for services.exe. Unable to proceed."
                )
                continue

            for offset in proc_layer.scan(
                context=context,
                scanner=scanners.BytesScanner(needle=b"Sc27"),
                sections=exe_range,
            ):
                yield from cls.enumerate_vista_or_later_header(
                    context,
                    service_table_name,
                    service_binary_dll_map,
                    proc_layer_name,
                    offset,
                )
