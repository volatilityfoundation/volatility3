# This file is Copyright 2025 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0


"""Plugin to extract clipboard data from Windows memory dumps."""

import logging
from typing import List

from volatility3.framework import interfaces, renderers, exceptions, constants
from volatility3.framework.configuration import requirements
from volatility3.framework.renderers import format_hints
from volatility3.plugins.windows import windowstations

vollog = logging.getLogger(__name__)


class Clipboard(interfaces.plugins.PluginInterface):
    """Reads clipboard data from a Windows memory dump.
    It looks at the tagCLIP list inside each WindowStation (pClipBase)
    and shows the clipboard formats and data stored there.

    Note: This is just a prototype. Right now it only works through
    WindowStation. In the future, support for USER handle table
    (tagSHAREDINFO) can be added when pClipBase is missing or zero"""

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
        """
        TODO: Later add USER handle table (tagSHAREDINFO) support
        to recover clipboard data when pClipBase is missing.
        """

        kernel_name = self.config["kernel"]

        for (
            winsta,
            station_name,
            session_id,
        ) in windowstations.WindowStations.scan_window_stations(
            self.context, self.config_path, kernel_name
        ):
            gui_table_name = winsta.vol.type_name.split(constants.BANG)[0]
            layer_name = winsta.vol.layer_name

            try:
                clip_count = int(winsta.cNumClipFormats)
                clip_base_ptr = int(winsta.pClipBase)
            except exceptions.InvalidAddressException:
                vollog.debug(f"Cannot read clipboard fields for station {station_name}")
                continue

            vollog.debug(
                f"Station={station_name} Session={session_id} "
                f"cNumClipFormats={clip_count} pClipBase={clip_base_ptr:#x}"
            )

            if clip_count == 0 or clip_count > 512:
                continue

            if clip_base_ptr <= 0xFFFF:
                continue

            try:
                tagclip_size = self.context.symbol_space.get_type(
                    gui_table_name + constants.BANG + "tagCLIP"
                ).size
            except exceptions.InvalidAddressException:
                vollog.debug(f"Cannot get tagCLIP size for {station_name}")
                continue

            for i in range(clip_count):
                try:
                    clip = self.context.object(
                        gui_table_name + constants.BANG + "tagCLIP",
                        layer_name=layer_name,
                        offset=clip_base_ptr + i * tagclip_size,
                    )

                    fmt_name = clip.get_format_name()
                    handle_val = int(clip.hData)

                    vollog.debug(f"  clip[{i}]: fmt={fmt_name} hData={handle_val:#x}")

                    # hData is a USER handle — not a direct pointer.
                    # Resolving it requires walking tagSHAREDINFO.aheList
                    # which is not yet implemented (see TODO above).
                    # For now we report format and handle without data.
                    data_display: interfaces.renderers.BaseAbsentValue | str = (
                        renderers.NotAvailableValue()
                    )

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

                except exceptions.InvalidAddressException as e:
                    vollog.debug(f"  clip[{i}]: {e}")
                    continue

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
