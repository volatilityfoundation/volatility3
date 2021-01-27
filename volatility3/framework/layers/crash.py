# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

import logging
import struct
from typing import Tuple, Optional

from volatility3.framework import constants, exceptions, interfaces
from volatility3.framework.layers import segmented
from volatility3.framework.symbols import intermed

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
    VALIDDUMP = 0x504d5544

    crashdump_json = 'crash'
    supported_dumptypes = [0x01]
    dump_header_name = '_DUMP_HEADER'

    _magic_struct = struct.Struct('<II')
    headerpages = 1

    def __init__(self, context: interfaces.context.ContextInterface, config_path: str, name: str) -> None:

        # Construct these so we can use self.config
        self._context = context
        self._config_path = config_path
        self._page_size = 0x1000
        self._base_layer = self.config["base_layer"]

        # Create a custom SymbolSpace
        self._crash_table_name = intermed.IntermediateSymbolTable.create(context, self._config_path, 'windows',
                                                                         self.crashdump_json)
        # Check Header
        hdr_layer = self._context.layers[self._base_layer]
        hdr_offset = 0
        self.check_header(hdr_layer, hdr_offset)

        # Need to create a header object
        header = self.context.object(self._crash_table_name + constants.BANG + self.dump_header_name,
                                     offset = hdr_offset,
                                     layer_name = self._base_layer)

        # Extract the DTB
        self.dtb = int(header.DirectoryTableBase)

        self.dump_type = int(header.DumpType)

        # Verify that it is a supported format
        if header.DumpType not in self.supported_dumptypes:
            vollog.log(constants.LOGLEVEL_VVVV, "unsupported dump format 0x{:x}".format(header.DumpType))
            raise WindowsCrashDumpFormatException(name, "unsupported dump format 0x{:x}".format(header.DumpType))

        super().__init__(context, config_path, name)

    def _load_segments(self) -> None:
        """Loads up the segments from the meta_layer."""
        header = self.context.object(self._crash_table_name + constants.BANG + self.dump_header_name,
                                     offset = 0,
                                     layer_name = self._base_layer)

        segments = []

        offset = self.headerpages
        header.PhysicalMemoryBlockBuffer.Run.count = header.PhysicalMemoryBlockBuffer.NumberOfRuns
        for x in header.PhysicalMemoryBlockBuffer.Run:
            segments.append((x.BasePage * 0x1000, offset * 0x1000, x.PageCount * 0x1000, x.PageCount * 0x1000))
            # print("Segments {:x} {:x} {:x}".format(x.BasePage * 0x1000,
            #                  offset * 0x1000,
            #                  x.PageCount * 0x1000))
            offset += x.PageCount

        if len(segments) == 0:
            raise WindowsCrashDumpFormatException(self.name, "No Crash segments defined in {}".format(self._base_layer))

        self._segments = segments

    @classmethod
    def check_header(cls, base_layer: interfaces.layers.DataLayerInterface, offset: int = 0) -> Tuple[int, int]:
        # Verify the Window's crash dump file magic

        try:
            header_data = base_layer.read(offset, cls._magic_struct.size)
        except exceptions.InvalidAddressException:
            raise WindowsCrashDumpFormatException(base_layer.name,
                                                  "Crashdump header not found at offset {}".format(offset))
        (signature, validdump) = cls._magic_struct.unpack(header_data)

        if signature != cls.SIGNATURE:
            raise WindowsCrashDumpFormatException(
                base_layer.name, "Bad signature 0x{:x} at file offset 0x{:x}".format(signature, offset))
        if validdump != cls.VALIDDUMP:
            raise WindowsCrashDumpFormatException(base_layer.name,
                                                  "Invalid dump 0x{:x} at file offset 0x{:x}".format(validdump, offset))

        return signature, validdump


class WindowsCrashDump64Layer(WindowsCrashDump32Layer):
    """A Windows crash format TranslationLayer.

    This TranslationLayer supports Microsoft complete memory dump files.
    It currently does not support kernel or small memory dump files.
    """

    VALIDDUMP = 0x34365544
    crashdump_json = 'crash64'
    dump_header_name = '_DUMP_HEADER64'
    supported_dumptypes = [0x1, 0x05]
    headerpages = 2

    def _load_segments(self) -> None:
        """Loads up the segments from the meta_layer."""

        segments = []

        summary_header = self.context.object(self._crash_table_name + constants.BANG + "_SUMMARY_DUMP64",
                                             offset = 0x2000,
                                             layer_name = self._base_layer)

        if self.dump_type == 0x1:
            header = self.context.object(self._crash_table_name + constants.BANG + self.dump_header_name,
                                         offset = 0,
                                         layer_name = self._base_layer)

            offset = self.headerpages
            header.PhysicalMemoryBlockBuffer.Run.count = header.PhysicalMemoryBlockBuffer.NumberOfRuns
            for x in header.PhysicalMemoryBlockBuffer.Run:
                segments.append((x.BasePage * 0x1000, offset * 0x1000, x.PageCount * 0x1000, x.PageCount * 0x1000))
                offset += x.PageCount

        elif self.dump_type == 0x05:
            summary_header.BufferLong.count = (summary_header.BitmapSize + 31) // 32
            previous_bit = 0
            start_position = 0
            # We cast as an int because we don't want to carry the context around with us for infinite loop reasons
            mapped_offset = int(summary_header.HeaderSize)
            current_word = None
            for bit_position in range(len(summary_header.BufferLong) * 32):
                if (bit_position % 32) == 0:
                    current_word = summary_header.BufferLong[bit_position // 32]
                current_bit = (current_word >> (bit_position % 32)) & 1
                if current_bit != previous_bit:
                    if previous_bit == 0:
                        # Start
                        start_position = bit_position
                    else:
                        # Finish
                        length = (bit_position - start_position) * 0x1000
                        segments.append((start_position * 0x1000, mapped_offset, length, length))
                        mapped_offset += length

                # Finish it off
                if bit_position == (len(summary_header.BufferLong) * 32) - 1 and current_bit == 1:
                    length = (bit_position - start_position) * 0x1000
                    segments.append((start_position * 0x1000, mapped_offset, length, length))
                    mapped_offset += length

                previous_bit = current_bit
        else:
            vollog.log(constants.LOGLEVEL_VVVV, "unsupported dump format 0x{:x}".format(self.dump_type))
            raise WindowsCrashDumpFormatException(self.name, "unsupported dump format 0x{:x}".format(self.dump_type))

        if len(segments) == 0:
            raise WindowsCrashDumpFormatException(self.name, "No Crash segments defined in {}".format(self._base_layer))

        self._segments = segments


class WindowsCrashDumpStacker(interfaces.automagic.StackerLayerInterface):
    stack_order = 11

    @classmethod
    def stack(cls,
              context: interfaces.context.ContextInterface,
              layer_name: str,
              progress_callback: constants.ProgressCallback = None) -> Optional[interfaces.layers.DataLayerInterface]:
        for layer in [WindowsCrashDump32Layer, WindowsCrashDump64Layer]:
            try:
                layer.check_header(context.layers[layer_name])
                new_name = context.layers.free_layer_name(layer.__name__)
                context.config[interfaces.configuration.path_join(new_name, "base_layer")] = layer_name
                return layer(context, new_name, new_name)
            except WindowsCrashDumpFormatException:
                pass
        return None
