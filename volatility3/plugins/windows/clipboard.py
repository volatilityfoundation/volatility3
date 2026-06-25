# This file is Copyright 2025 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
"""Plugin to extract clipboard data from Windows memory dumps."""

import logging
from typing import List

from volatility3.framework import interfaces, renderers, exceptions
from volatility3.framework.configuration import requirements
from volatility3.framework.renderers import format_hints
from volatility3.plugins.windows import windowstations

vollog = logging.getLogger(__name__)


class Clipboard(interfaces.plugins.PluginInterface):
    """Extracts clipboard data from a Windows memory image."""

    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
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

    def _generator(self):
        """Walk window stations and extract clipboard data."""
        kernel_name = self.config["kernel"]

        for winsta, station_name, session_id in windowstations.WindowStations.scan_window_stations(
            self.context, self.config_path, kernel_name
        ):
            try:
                clip_count = int(winsta.cNumClipFormats)
                if clip_count == 0 or clip_count > 512:
                    continue

                clip_array = winsta.pClipBase.dereference()

            except exceptions.InvalidAddressException:
                vollog.debug(
                    f"Could not read clipboard base for station {station_name}"
                )
                continue

            for i in range(clip_count):
                try:
                    clip = clip_array[i]
                    fmt_name = clip.get_format_name()
                    handle_val = int(clip.hData)

                    clip_data_ptr = clip.hData.dereference()
                    data = clip_data_ptr.get_data()

                    if data is None:
                        data_display = renderers.NotAvailableValue()
                    else:
                        text = clip_data_ptr.get_text(fmt_name)
                        if text:
                            data_display = text
                        else:
                            data_display = data.hex()

                except exceptions.InvalidAddressException:
                    fmt_name = renderers.NotAvailableValue()
                    handle_val = 0
                    data_display = renderers.NotAvailableValue()

                yield (
                    0,
                    (
                        session_id,
                        station_name,
                        fmt_name,
                        format_hints.Hex(handle_val),
                        data_display,
                    ),
                )

    def run(self):
        return renderers.TreeGrid(
            [
                ("Session", int),
                ("WindowStation", str),
                ("Format", str),
                ("Handle", format_hints.Hex),
                ("Data", str),
            ],
            self._generator(),
        )

