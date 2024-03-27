# This file is Copyright 2021 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
import contextlib
import logging
import struct
from typing import Tuple, Optional

from volatility3.framework import constants, exceptions, interfaces
from volatility3.framework.layers import segmented
from volatility3.framework.symbols import intermed
from volatility3.framework.symbols.windows.extensions import crash

vollog = logging.getLogger(__name__)


class WindowsCrashDumpFormatException(exceptions.LayerException):
    """Thrown when an error occurs with the underlying Crash file format."""


class WindowsCrashDump32Layer(segmented.SegmentedLayer):
    """A Windows crash format TranslationLayer.
    This TranslationLayer supports Microsoft complete memory dump files.
    It currently does not support kernel or small memory dump files.
    """

    provides = {"type": "physical"}

    SIGNATURE = 0x45474150
    VALIDDUMP = 0x504D5544

    crashdump_json = "crash"
    supported_dumptypes = [0x01, 0x05]  # we need 0x5 for 32-bit bitmaps
    dump_header_name = "_DUMP_HEADER"

    _magic_struct = struct.Struct("<II")
    headerpages = 1

    def __init__(
        self, context: interfaces.context.ContextInterface, config_path: str, name: str
    ) -> None:
        # Construct these so we can use self.config
        self._context = context
        self._config_path = config_path
        self._page_size = 0x1000
        # no try/except needed. as seen in vmware.py
        self._base_layer = self.config["base_layer"]

        # Create a custom SymbolSpace
        self._crash_table_name = intermed.IntermediateSymbolTable.create(
            context, self._config_path, "windows", self.crashdump_json
        )

        # the _SUMMARY_DUMP is shared between 32- and 64-bit
        self._crash_common_table_name = intermed.IntermediateSymbolTable.create(
            context,
            self._config_path,
            "windows",
            "crash_common",
            class_types=crash.class_types,
        )

        # Check Header
        hdr_layer = self._context.layers[self._base_layer]
        hdr_offset = 0
        self.check_header(hdr_layer, hdr_offset)

        # Need to create a header object
        header = self.get_header()

        # Extract the DTB
        self.dtb = int(header.DirectoryTableBase)

        self.dump_type = int(header.DumpType)

        # Verify that it is a supported format
        if header.DumpType not in self.supported_dumptypes:
            vollog.log(
                constants.LOGLEVEL_VVVV,
                f"unsupported dump format 0x{header.DumpType:x}",
            )
            raise WindowsCrashDumpFormatException(
                name, f"unsupported dump format 0x{header.DumpType:x}"
            )

        # Then call the super, which will call load_segments (which needs the base_layer before it'll work)
        super().__init__(context, config_path, name)

    def get_header(self) -> interfaces.objects.ObjectInterface:
        return self.context.object(
            self._crash_table_name + constants.BANG + self.dump_header_name,
            offset=0,
            layer_name=self._base_layer,
        )

    def get_summary_header(self) -> interfaces.objects.ObjectInterface:
        return self.context.object(
            self._crash_common_table_name + constants.BANG + "_SUMMARY_DUMP",
            offset=0x1000 * self.headerpages,
            layer_name=self._base_layer,
        )

    def _load_segments(self) -> None:
        """Loads up the segments from the meta_layer."""

        segments = []

        if self.dump_type == 0x1:
            header = self.context.object(
                self._crash_table_name + constants.BANG + self.dump_header_name,
                offset=0,
                layer_name=self._base_layer,
            )

            offset = self.headerpages
            header.PhysicalMemoryBlockBuffer.Run.count = (
                header.PhysicalMemoryBlockBuffer.NumberOfRuns
            )
            for run in header.PhysicalMemoryBlockBuffer.Run:
                segments.append(
                    (
                        run.BasePage * 0x1000,
                        offset * 0x1000,
                        run.PageCount * 0x1000,
                        run.PageCount * 0x1000,
                    )
                )
                offset += run.PageCount

        elif self.dump_type == 0x05:
            summary_header = self.get_summary_header()
            first_bit = None  # First bit in a run
            first_offset = 0  # File offset of first bit
            last_bit_seen = 0  # Most recent bit processed
            offset = summary_header.HeaderSize  # Size of file headers
            buffer_char = summary_header.get_buffer_char()
            buffer_long = summary_header.get_buffer_long()

            for outer_index in range(0, ((summary_header.BitmapSize + 31) // 32)):
                if buffer_long[outer_index] == 0:
                    if first_bit is not None:
                        last_bit = ((outer_index - 1) * 32) + 31
                        segment_length = (last_bit - first_bit + 1) * 0x1000
                        segments.append(
                            (
                                first_bit * 0x1000,
                                first_offset,
                                segment_length,
                                segment_length,
                            )
                        )
                        first_bit = None
                elif buffer_long[outer_index] == 0xFFFFFFFF:
                    if first_bit is None:
                        first_offset = offset
                        first_bit = outer_index * 32
                    offset = offset + (32 * 0x1000)
                else:
                    for inner_index in range(0, 32):
                        bit_addr = outer_index * 32 + inner_index
                        if (buffer_char[bit_addr >> 3] >> (bit_addr & 0x7)) & 1:
                            if first_bit is None:
                                first_offset = offset
                                first_bit = bit_addr
                            offset = offset + 0x1000
                        else:
                            if first_bit is not None:
                                segment_length = (
                                    (bit_addr - 1) - first_bit + 1
                                ) * 0x1000
                                segments.append(
                                    (
                                        first_bit * 0x1000,
                                        first_offset,
                                        segment_length,
                                        segment_length,
                                    )
                                )
                                first_bit = None
                last_bit_seen = (outer_index * 32) + 31

            if first_bit is not None:
                segment_length = (last_bit_seen - first_bit + 1) * 0x1000
                segments.append(
                    (first_bit * 0x1000, first_offset, segment_length, segment_length)
                )
        else:
            vollog.log(
                constants.LOGLEVEL_VVVV, f"unsupported dump format 0x{self.dump_type:x}"
            )
            raise WindowsCrashDumpFormatException(
                self.name, f"unsupported dump format 0x{self.dump_type:x}"
            )

        if len(segments) == 0:
            raise WindowsCrashDumpFormatException(
                self.name, f"No Crash segments defined in {self._base_layer}"
            )
        else:
            # report the segments for debugging. this is valuable for dev/troubleshooting but
            # not important enough for a dedicated plugin.
            for idx, (start_position, mapped_offset, length, _) in enumerate(segments):
                vollog.log(
                    constants.LOGLEVEL_VVVV,
                    "Segment {}: Position {:#x} Offset {:#x} Length {:#x}".format(
                        idx, start_position, mapped_offset, length
                    ),
                )

        self._segments = segments

    @classmethod
    def check_header(
        cls, base_layer: interfaces.layers.DataLayerInterface, offset: int = 0
    ) -> Tuple[int, int]:
        # Verify the Window's crash dump file magic

        try:
            header_data = base_layer.read(offset, cls._magic_struct.size)
        except exceptions.InvalidAddressException:
            raise WindowsCrashDumpFormatException(
                base_layer.name, f"Crashdump header not found at offset {offset}"
            )
        (signature, validdump) = cls._magic_struct.unpack(header_data)

        if signature != cls.SIGNATURE:
            raise WindowsCrashDumpFormatException(
                base_layer.name,
                f"Bad signature 0x{signature:x} at file offset 0x{offset:x}",
            )
        if validdump != cls.VALIDDUMP:
            raise WindowsCrashDumpFormatException(
                base_layer.name,
                f"Invalid dump 0x{validdump:x} at file offset 0x{offset:x}",
            )

        return signature, validdump


class WindowsCrashDump64Layer(WindowsCrashDump32Layer):
    """A Windows crash format TranslationLayer.
    This TranslationLayer supports Microsoft complete memory dump files.
    It currently does not support kernel or small memory dump files.
    """

    VALIDDUMP = 0x34365544
    crashdump_json = "crash64"
    dump_header_name = "_DUMP_HEADER64"
    supported_dumptypes = [0x1, 0x05]
    headerpages = 2


class WindowsCrashDumpStacker(interfaces.automagic.StackerLayerInterface):
    stack_order = 11

    @classmethod
    def stack(
        cls,
        context: interfaces.context.ContextInterface,
        layer_name: str,
        progress_callback: constants.ProgressCallback = None,
    ) -> Optional[interfaces.layers.DataLayerInterface]:
        for layer in [WindowsCrashDump32Layer, WindowsCrashDump64Layer]:
            try:
                layer.check_header(context.layers[layer_name])
                new_name = context.layers.free_layer_name(layer.__name__)
                context.config[
                    interfaces.configuration.path_join(new_name, "base_layer")
                ] = layer_name
                return layer(context, new_name, new_name)
            except WindowsCrashDumpFormatException as excp:
                vollog.log(
                    constants.LOGLEVEL_VVVV, f"Exception reading crashdump: {excp}"
                )
        return None
