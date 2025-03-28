# This file is Copyright 2025 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
import logging
from typing import List, Iterable

from volatility3.framework import interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.renderers import format_hints
from volatility3.plugins.windows import windowstations

vollog = logging.getLogger(__name__)


class Desktops(interfaces.plugins.PluginInterface):
    """Enumerates the Desktop instances of each Window Station"""

    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 0)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.implementation = self.list_desktops

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
    def list_desktops(
        cls,
        context: interfaces.context.ContextInterface,
        config_path: str,
        kernel_module_name: str,
    ) -> Iterable[interfaces.objects.ObjectInterface]:
        """
        Uses `scan_window_stations` to find each window station
        For each found, enumerates its desktops followed by the
        threads of each desktop.
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
                # for each desktop, walk its threads
                for _thread, process_name, process_pid in desktop.get_threads():
                    yield format_hints.Hex(
                        desktop.vol.offset
                    ), station_name, session_id, desktop_name, process_name, process_pid

    def _generator(self):
        kernel_name = self.config["kernel"]

        # call the implementation for finding desktops
        # yield the information, which will include the owning window station and process
        for desktop_info in self.implementation(
            self.context, self.config_path, kernel_name
        ):
            yield 0, desktop_info

    def run(self):
        return renderers.TreeGrid(
            [
                ("Offset", format_hints.Hex),
                ("Window Station", str),
                ("Session", int),
                ("Desktop", str),
                ("Process", str),
                ("PID", int),
            ],
            self._generator(),
        )
