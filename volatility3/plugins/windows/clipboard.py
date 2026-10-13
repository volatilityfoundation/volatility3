# This file is Copyright 2025 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0


"""Plugin to enumerate clipboard formats from Windows memory dumps."""

import logging
from typing import Iterable, List, Tuple

from volatility3.framework import interfaces, renderers, exceptions
from volatility3.framework.configuration import requirements
from volatility3.framework.renderers import format_hints
from volatility3.plugins.windows import windowstations

vollog = logging.getLogger(__name__)


class Clipboard(interfaces.plugins.PluginInterface):
    """Enumerates clipboard formats and USER handles for each Window Station.

    Clipboard contents are not recovered because the GUI symbol tables do not
    currently expose the session's ``gSharedInfo`` symbol needed to resolve
    USER handles to ``tagCLIPDATA`` objects.
    """

    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Windows kernel",
                architectures=["Intel64"],
            ),
            requirements.VersionRequirement(
                name="windowstations",
                component=windowstations.WindowStations,
                version=(1, 0, 0),
            ),
        ]

    @classmethod
    def list_clipboard_formats(
        cls,
        context: interfaces.context.ContextInterface,
        config_path: str,
        kernel_module_name: str,
    ) -> Iterable[Tuple[int, str, str, int]]:
        """Yields session, Window Station, format name, and USER handle."""
        for (
            winsta,
            station_name,
            session_id,
        ) in windowstations.WindowStations.scan_window_stations(
            context, config_path, kernel_module_name
        ):
            try:
                clip_count = int(winsta.cNumClipFormats)
                clip_base = winsta.pClipBase
            except exceptions.InvalidAddressException:
                vollog.debug(
                    "Cannot read clipboard fields for station %s", station_name
                )
                continue

            if clip_count <= 0 or not clip_base:
                continue

            try:
                clip_array = clip_base.dereference()
            except exceptions.InvalidAddressException:
                vollog.debug("Cannot read clipboard array for station %s", station_name)
                continue

            vollog.debug(
                "Station=%s Session=%s cNumClipFormats=%s pClipBase=%#x",
                station_name,
                session_id,
                clip_count,
                int(clip_base),
            )

            for index, clip in enumerate(clip_array):
                if index >= clip_count:
                    break
                try:
                    fmt_name = clip.get_format_name()
                    handle_val = int(clip.hData)
                    vollog.debug(
                        "clip[%s]: fmt=%s hData=%#x",
                        index,
                        fmt_name,
                        handle_val,
                    )
                    yield session_id, station_name, fmt_name, handle_val
                except exceptions.InvalidAddressException as e:
                    vollog.debug("clip[%s]: %s", index, e)
                    continue

    def _generator(self):
        for (
            session_id,
            station_name,
            fmt_name,
            handle_val,
        ) in self.list_clipboard_formats(
            self.context, self.config_path, self.config["kernel"]
        ):
            yield (
                0,
                (
                    session_id,
                    station_name,
                    fmt_name,
                    format_hints.Hex(handle_val),
                ),
            )

    def run(self):
        return renderers.TreeGrid(
            [
                ("Session", int),
                ("WindowStation", str),
                ("Format", str),
                ("Handle", format_hints.Hex),
            ],
            self._generator(),
        )
