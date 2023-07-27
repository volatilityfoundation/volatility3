# This file is Copyright 2022 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

"""Functions that read AVML files.

The user of the file doesn't have to worry about the compression,
but random access is not allowed."""
import ctypes
import logging
import struct
from typing import Tuple, List, Optional

from volatility3.framework import exceptions, interfaces, constants
from volatility3.framework.layers import segmented

vollog = logging.getLogger(__name__)

try:
    # TODO: Find library for windows if needed
    try:
        # Linux
        lib_snappy = ctypes.cdll.LoadLibrary("libsnappy.so.1")
    except OSError:
        lib_snappy = None

    try:
        # macOS
        lib_snappy = ctypes.cdll.LoadLibrary("libsnappy.1.dylib")
    except OSError:
        lib_snappy = None

    try:
        if not lib_snappy:
            # Windows 64
            lib_snappy = ctypes.cdll.LoadLibrary("snappy64")
    except OSError:
        lib_snappy = None

    if not lib_snappy:
        # Windows 32
        lib_snappy = ctypes.cdll.LoadLibrary("snappy32")

    __snappy_uncompress = lib_snappy.snappy_uncompress
    __snappy_uncompressed_length = lib_snappy.snappy_uncompressed_length

    HAS_SNAPPY = True
except (AttributeError, OSError):
    HAS_SNAPPY = False


class SnappyException(exceptions.VolatilityException):
    pass


def uncompress(s):
    """Uncompress a snappy compressed string."""
    ulen = ctypes.c_int(0)
    cresult = __snappy_uncompressed_length(s, len(s), ctypes.byref(ulen))
    if cresult != 0:
        raise SnappyException(f"Error in snappy_uncompressed_length: {cresult}")
    ubuf = ctypes.create_string_buffer(ulen.value)
    cresult = __snappy_uncompress(s, len(s), ubuf, ctypes.byref(ulen))
    if cresult != 0:
        raise SnappyException(f"Error in snappy_uncompress: {cresult}")
    return ubuf.raw


class AVMLLayer(segmented.NonLinearlySegmentedLayer):
    """A Lime format TranslationLayer.

    Lime is generally used to store physical memory images where there
    are large holes in the physical layer
    """

    def __init__(self, *args, **kwargs):
        self._compressed = {}
        super().__init__(*args, **kwargs)

    @classmethod
    def _check_header(cls, layer: interfaces.layers.DataLayerInterface):
        header_structure = "<II"
        magic, version = struct.unpack(
            header_structure,
            layer.read(layer.minimum_address, struct.calcsize(header_structure)),
        )
        if magic not in [0x4C4D5641] or version != 2:
            raise exceptions.LayerException("File not in AVML format")
        if not HAS_SNAPPY:
            vollog.warning(
                "AVML file detected, but snappy library could not be found\n"
                "Please install the snappy from your distribution or https://google.github.io/snappy/."
            )
            raise exceptions.LayerException(
                "AVML format dependencies not satisfied (snappy)"
            )

    def _load_segments(self) -> None:
        base_layer = self.context.layers[self._base_layer]
        offset = base_layer.minimum_address
        while offset + 4 < base_layer.maximum_address:
            avml_header_structure = "<IIQQQ"
            avml_header_size = struct.calcsize(avml_header_structure)
            avml_header_data = base_layer.read(offset, avml_header_size)
            magic, version, start, end, padding = struct.unpack(
                avml_header_structure, avml_header_data
            )

            if magic not in [0x4C4D5641] or version != 2:
                raise exceptions.LayerException("File not completely in AVML format")
            chunk_data = base_layer.read(
                offset + avml_header_size,
                min(
                    end - start,
                    base_layer.maximum_address - (offset + avml_header_size),
                ),
            )
            segments, consumed = self._read_snappy_frames(chunk_data, end - start)
            # The returned segments are accurate the chunk_data that was passed in, but needs shifting
            for thing, mapped_offset, size, mapped_size, compressed in segments:
                self._segments.append(
                    (
                        thing + start,
                        offset + mapped_offset + avml_header_size,
                        size,
                        mapped_size,
                    )
                )
                self._compressed[offset + mapped_offset + avml_header_size] = compressed

            # TODO: Check whatever the remaining 8 bytes are
            offset += avml_header_size + consumed + 8

    def _read_snappy_frames(
        self, data: bytes, expected_length: int
    ) -> Tuple[List[Tuple[int, int, int, int, bool]], int]:
        """
        Reads a framed-format snappy stream

        Args:
            data: The stream to read
            expected_length: How big the decompressed stream is expected to be (termination limit)

        Returns:
            (offset, mapped_offset, length, mapped_length, compressed) relative to the data chunk (ie, not relative to the file start)
        """
        segments = []
        decompressed_len = 0
        offset = 0
        crc_len = 4
        frame_header_struct = "<L"
        frame_header_len = struct.calcsize(frame_header_struct)
        while decompressed_len <= expected_length:
            if offset + frame_header_len < len(data):
                frame_header = data[offset : offset + frame_header_len]
                frame_header_val = struct.unpack("<L", frame_header)[0]
                frame_type, frame_size = frame_header_val & 0xFF, frame_header_val >> 8
                if frame_type == 0xFF:
                    if (
                        data[
                            offset
                            + frame_header_len : offset
                            + frame_header_len
                            + frame_size
                        ]
                        != b"sNaPpY"
                    ):
                        raise ValueError(f"Snappy header missing at offset: {offset}")
                elif frame_type in [0x00, 0x01]:
                    # CRC + (Un)compressed data
                    mapped_start = offset + frame_header_len
                    # frame_crc = data[mapped_start: mapped_start + crc_len]
                    frame_data = data[
                        mapped_start + crc_len : mapped_start + frame_size
                    ]
                    if frame_type == 0x00:
                        # Compressed data
                        frame_data = uncompress(frame_data)
                    # TODO: Verify CRC
                    segments.append(
                        (
                            decompressed_len,
                            mapped_start + crc_len,
                            len(frame_data),
                            frame_size - crc_len,
                            frame_type == 0x00,
                        )
                    )
                    decompressed_len += len(frame_data)
                elif frame_type in range(0x2, 0x80):
                    # Unskippable
                    raise exceptions.LayerException(
                        f"Unskippable chunk of type {frame_type} found: {offset}"
                    )
                offset += frame_header_len + frame_size
        return segments, offset

    def _decode_data(
        self, data: bytes, mapped_offset: int, offset: int, output_length: int
    ) -> bytes:
        start_offset, _, _, _ = self._find_segment(offset)
        if self._compressed[mapped_offset]:
            decoded_data = uncompress(data)
        else:
            decoded_data = data
        decoded_data = decoded_data[offset - start_offset :]
        decoded_data = decoded_data[:output_length]
        return decoded_data


class AVMLStacker(interfaces.automagic.StackerLayerInterface):
    stack_order = 10

    @classmethod
    def stack(
        cls,
        context: interfaces.context.ContextInterface,
        layer_name: str,
        progress_callback: constants.ProgressCallback = None,
    ) -> Optional[interfaces.layers.DataLayerInterface]:
        try:
            AVMLLayer._check_header(context.layers[layer_name])
        except exceptions.LayerException:
            return None
        new_name = context.layers.free_layer_name("AVMLLayer")
        context.config[
            interfaces.configuration.path_join(new_name, "base_layer")
        ] = layer_name
        return AVMLLayer(context, new_name, new_name)
