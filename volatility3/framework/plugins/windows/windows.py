# This file is Copyright 2025 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
import logging
from typing import List, Iterable

from volatility3.framework import interfaces, renderers, exceptions
from volatility3.framework.objects import utility
from volatility3.framework.configuration import requirements
from volatility3.framework.renderers import format_hints
from volatility3.plugins.windows import windowstations

vollog = logging.getLogger(__name__)


class Windows(interfaces.plugins.PluginInterface):
    """Enumerates the Windows of Desktop instances"""

    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        # Since we're calling the plugin, make sure we have the plugin's requirements
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Windows kernel",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.VersionRequirement(
                name="windowstations",
                component=windowstations.WindowStations,
                version=(1, 0, 0),
            ),
        ]

    @classmethod
    def list_windows(
        cls,
        context: interfaces.context.ContextInterface,
        config_path: str,
        kernel_module_name: str,
    ) -> Iterable[interfaces.objects.ObjectInterface]:
        """
        Enumerates the desktops of each window station
        For each found, enumerates its windows within the desktop
        """
        kernel = context.modules[kernel_module_name]

        for (
            winsta,
            station_name,
            session_id,
        ) in windowstations.WindowStations.scan_window_stations(
            context, config_path, kernel_module_name
        ):
            # for each window station, walk its list of desktops
            for desktop, desktop_name in winsta.desktops(kernel.symbol_table_name):
                try:
                    top_window = desktop.pDeskInfo.spwnd
                except exceptions.InvalidAddressException:
                    vollog.debug(
                        f"Desktop with name {desktop_name} in window station {station_name} has a broken window pointer."
                    )
                    continue

                for window, window_name in desktop.windows(top_window):
                    yield station_name, desktop_name, window, window_name

    def _generator(self):
        kernel_name = self.config["kernel"]

        # call the implementation for finding windows and gather attributes
        for station_name, desktop_name, window, window_name in self.list_windows(
            self.context, self.config_path, kernel_name
        ):
            # We need a valid process and session id for the window to display it
            process = window.get_process()
            process_name = None
            if process:
                try:
                    process_name = utility.array_to_string(process.ImageFileName)
                    process_pid = process.UniqueProcessId
                except exceptions.InvalidAddressException:
                    vollog.debug(
                        f"Unable to read name and pid of the process for window {window.vol.offset:#x}"
                    )

            if process_name is None:
                vollog.debug(
                    f"Invalid process reference for the process hosting window {window.vol.offset:#x}"
                )
                continue

            sess_id = window.get_session_id()
            if sess_id is None:
                vollog.debug(
                    f"Unable to read session id of the process for window {window.vol.offset:#x} in process {process_name}"
                )
                continue

            # procedures can be empty, but if set, should be a valid pointer
            window_proc = window.get_window_procedure()
            if window_proc is None:
                window_proc = renderers.NotAvailableValue()
            elif window_proc == 0 or window_proc > 0x1000:
                window_proc = format_hints.Hex(window_proc)
            else:
                vollog.debug(
                    f"Invalid window procedure {window_proc} for the window {window.vol.offset:#x}"
                )
                continue

            yield 0, (
                format_hints.Hex(window.vol.offset),
                station_name,
                sess_id,
                desktop_name,
                window_name or renderers.NotAvailableValue(),
                window_proc,
                process_name,
                process_pid,
            )

    def run(self):
        return renderers.TreeGrid(
            [
                ("Offset", format_hints.Hex),
                ("Station", str),
                ("Session", int),
                ("Desktop", str),
                ("Window", str),
                ("Procedure", format_hints.Hex),
                ("Process", str),
                ("PID", int),
            ],
            self._generator(),
        )
