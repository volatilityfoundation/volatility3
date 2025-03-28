# This file is Copyright 2025 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
import logging
from typing import List, Iterable, Tuple

from volatility3.framework import interfaces
from volatility3.framework.configuration import requirements
from volatility3.framework.renderers import format_hints
from volatility3.plugins.windows import desktops, windowstations

vollog = logging.getLogger(__name__)


class DeskScan(desktops.Desktops):
    """Scans for the Desktop instances of each Window Station"""

    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 0)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.implementation = self.scan_desktops

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
                name="desktops", component=desktops.Desktops, version=(1, 0, 0)
            ),
            requirements.VersionRequirement(
                name="windowstations",
                component=windowstations.WindowStations,
                version=(1, 0, 0),
            ),
        ]

    @classmethod
    def scan_desktops(
        cls,
        context: interfaces.context.ContextInterface,
        config_path: str,
        kernel_module_name: str,
    ) -> Iterable[Tuple[int, str, int, str, str, int]]:
        """
        Yields the information about each desktop and desktop thread needed for analysis

        The tuple yielded includes the:
            Virtual address of the desktop
            The window station name
            The session id
            Desktop name
            Process name
            Process ID (PID)
        """
        kernel = context.modules[kernel_module_name]

        for desktop in windowstations.WindowStations.scan_gui_object(
            context, config_path, kernel_module_name, b"Desk", "tagDESKTOP"
        ):
            desktop_name = desktop.get_name(kernel.symbol_table_name)
            if not desktop_name:
                continue

            winsta = desktop.get_window_station()
            if not winsta:
                continue

            winsta_name, session_id = winsta.get_info(kernel.symbol_table_name)
            if not winsta_name or session_id is None:
                continue

            for _thread, process_name, process_pid in desktop.get_threads():
                yield format_hints.Hex(
                    desktop.vol.offset
                ), winsta_name, session_id, desktop_name, process_name, process_pid
