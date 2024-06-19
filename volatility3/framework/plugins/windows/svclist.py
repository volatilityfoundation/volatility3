# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

import logging

from typing import List

from volatility3.framework import interfaces, exceptions, symbols
from volatility3.framework.configuration import requirements
from volatility3.framework.symbols.windows import versions
from volatility3.plugins.windows import svcscan, pslist
from volatility3.framework.layers import scanners

vollog = logging.getLogger(__name__)


class SvcList(svcscan.SvcScan):
    """Lists services contained with the services.exe doubly linked list of services"""

    _version = (1, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        # Since we're calling the plugin, make sure we have the plugin's requirements
        return [
            requirements.PluginRequirement(
                name="svcscan", plugin=svcscan.SvcScan, version=(2, 0, 0)
            ),
        ]

    def _get_exe_range(self, proc):
        """
        Returns a tuple of starting,ending address for
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

    def service_list(self, service_table_name, service_binary_dll_map, filter_func):
        kernel = self.context.modules[self.config["kernel"]]

        if not symbols.symbol_table_is_64bit(
            self.context, kernel.symbol_table_name
        ) or not versions.is_win10_15063_or_later(
            context=self.context, symbol_table=kernel.symbol_table_name
        ):
            vollog.info(
                "This plugin only supports Windows 10 version 15063+ 64bit Windows memory samples"
            )
            return

        for proc in pslist.PsList.list_processes(
            context=self.context,
            layer_name=kernel.layer_name,
            symbol_table=kernel.symbol_table_name,
            filter_func=filter_func,
        ):
            try:
                layer_name = proc.add_process_layer()
            except exceptions.InvalidAddressException:
                vollog.warning(
                    "Unable to access memory of services.exe running with PID: {}".format(
                        proc.UniqueProcessId
                    )
                )
                continue

            layer = self.context.layers[layer_name]

            exe_range = self._get_exe_range(proc)
            if not exe_range:
                vollog.warning(
                    "Could not find the application executable VAD for services.exe. Unable to proceed."
                )
                continue

            for offset in layer.scan(
                context=self.context,
                scanner=scanners.BytesScanner(needle=b"Sc27"),
                sections=exe_range,
            ):
                for record in self.enumerate_vista_or_later_header(
                    service_table_name, service_binary_dll_map, layer_name, offset
                ):
                    yield record

    def _generator(self):
        service_table_name, service_binary_dll_map, filter_func = self.get_prereq_info()

        for record in self.service_list(
            service_table_name, service_binary_dll_map, filter_func
        ):
            yield (0, record)
