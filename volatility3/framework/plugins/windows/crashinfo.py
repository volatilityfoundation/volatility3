# This file is Copyright 2021 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

import logging
import datetime
from volatility3.framework import interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.renderers import format_hints, conversion
from volatility3.framework.objects import utility
from volatility3.framework.layers import crash

vollog = logging.getLogger(__name__)


class Crashinfo(interfaces.plugins.PluginInterface):
    """Lists the information from a Windows crash dump."""

    _required_framework_version = (2, 0, 0)

    @classmethod
    def get_requirements(cls):
        return [
            requirements.TranslationLayerRequirement(
                name="primary",
                description="Memory layer for the kernel",
                architectures=["Intel32", "Intel64"],
            ),
        ]

    def _generator(self, layer: crash.WindowsCrashDump32Layer):
        header = layer.get_header()
        uptime = datetime.timedelta(microseconds=int(header.SystemUpTime) / 10)

        if header.DumpType == 0x1:
            dump_type = "Full Dump (0x1)"
        elif header.DumpType == 0x5:
            dump_type = "Bitmap Dump (0x5)"
        else:
            # this should never happen since the crash layer only accepts 0x1 and 0x5
            dump_type = f"Unknown/Unsupported ({header.DumpType:#x})"

        if header.DumpType == 0x5:
            summary_header = layer.get_summary_header()
            bitmap_header_size = format_hints.Hex(summary_header.HeaderSize)
            bitmap_size = format_hints.Hex(summary_header.BitmapSize)
            bitmap_pages = format_hints.Hex(summary_header.Pages)
        else:
            bitmap_header_size = bitmap_size = bitmap_pages = (
                renderers.NotApplicableValue()
            )

        yield (
            0,
            (
                utility.array_to_string(header.Signature),
                header.MajorVersion,
                header.MinorVersion,
                format_hints.Hex(header.DirectoryTableBase),
                format_hints.Hex(header.PfnDataBase),
                format_hints.Hex(header.PsLoadedModuleList),
                format_hints.Hex(header.PsActiveProcessHead),
                header.MachineImageType,
                header.NumberProcessors,
                format_hints.Hex(header.KdDebuggerDataBlock),
                dump_type,
                str(uptime),
                utility.array_to_string(header.Comment),
                conversion.wintime_to_datetime(header.SystemTime),
                bitmap_header_size,
                bitmap_size,
                bitmap_pages,
            ),
        )

    def run(self):
        crash_layer = None
        for layer_name in self._context.layers:
            layer = self._context.layers[layer_name]
            if isinstance(layer, crash.WindowsCrashDump32Layer):
                crash_layer = layer
                break

        if crash_layer is None:
            vollog.error("This plugin requires a Windows crash dump")
            raise

        return renderers.TreeGrid(
            [
                ("Signature", str),
                ("MajorVersion", int),
                ("MinorVersion", int),
                ("DirectoryTableBase", format_hints.Hex),
                ("PfnDataBase", format_hints.Hex),
                ("PsLoadedModuleList", format_hints.Hex),
                ("PsActiveProcessHead", format_hints.Hex),
                ("MachineImageType", int),
                ("NumberProcessors", int),
                ("KdDebuggerDataBlock", format_hints.Hex),
                ("DumpType", str),
                ("SystemUpTime", str),
                ("Comment", str),
                ("SystemTime", datetime.datetime),
                ("BitmapHeaderSize", format_hints.Hex),
                ("BitmapSize", format_hints.Hex),
                ("BitmapPages", format_hints.Hex),
            ],
            self._generator(crash_layer),
        )
