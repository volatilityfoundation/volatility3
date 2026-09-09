# This file is Copyright 2026 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
"""A translation layer for Comae/MAGNET DumpIt compressed memory images (.zdmp).

The layer walks the ZDMP block chain at construction time and decompresses blocks
on demand, allowing a .zdmp image to be analysed without first materializing a
separate decompressed copy:

    vol -f memory.zdmp windows.pslist

Container format
----------------
File header, 4096 bytes::

    0x00  u32  signature       "ZDMP"
    0x04  u32  version
    0x08  u64  uncompressed size
    0x10  u32  block size          (0x200000 observed)
    0x14  u16  data type           1 = compression
    0x16  u16  compression format  2 = LZNT1

Blocks follow contiguously from offset 0x1000::

    0x00  u32  signature       "ZBLK"
    0x04  u32  compressed size
    0x08  u32  checksum
    0x0c  payload

The next block begins at ``current + 12 + compressed size``; there is no index,
so the chain is walked once at layer construction to build the segment list.

Two encoding details are easy to miss and produce silent corruption if ignored:

* a block whose payload size equals the container block size is stored **verbatim**,
  because DumpIt falls back to raw storage when compression does not help;
* a block that decompresses short is **zero padded** up to the block size.

The decompressed stream is a Microsoft crash dump, so the existing
``WindowsCrashDump64Layer`` stacks directly on top of this one.

LZNT1 is implemented here so the layer introduces no new dependency. If
``dissect.util`` is installed, its LZNT1 decompressor is used instead.
"""

import binascii
import collections
import logging
import struct
from typing import Optional

from volatility3.framework import constants, exceptions, interfaces
from volatility3.framework.layers import segmented

vollog = logging.getLogger(__name__)

try:  # optional accelerator; the pure-Python implementation below is the default
    from dissect.util.compression import lznt1 as _dissect_lznt1
except ImportError:
    _dissect_lznt1 = None


def lznt1_decompress(data: bytes) -> bytes:
    """Decompress an LZNT1 stream (MS-XCA section 2.5).

    The stream is a sequence of chunks, each introduced by a 16-bit header whose
    top bit marks the chunk as compressed and whose low 12 bits hold its encoded
    length minus one. Within a compressed chunk, a flag byte governs the next
    eight tokens: a clear bit denotes a literal byte, a set bit a 16-bit
    back-reference whose split between length and displacement widens as the
    output grows.
    """
    out = bytearray()
    pos = 0
    end = len(data)

    while pos + 2 <= end:
        header = data[pos] | (data[pos + 1] << 8)
        pos += 2
        if header == 0:
            break

        if header & 0x3000 != 0x3000:
            raise ValueError("Invalid LZNT1 chunk signature")

        size = (header & 0x0FFF) + 1
        if pos + size > end:
            raise ValueError("Truncated LZNT1 chunk")
        chunk = data[pos : pos + size]
        pos += size
        if not header & 0x8000:
            out += chunk
            continue

        chunk_start = len(out)
        idx = 0
        while idx < len(chunk):
            flags = chunk[idx]
            idx += 1
            for bit in range(8):
                if idx >= len(chunk):
                    break
                if not flags & (1 << bit):
                    out.append(chunk[idx])
                    idx += 1
                    continue

                if idx + 1 >= len(chunk):
                    raise ValueError("Truncated LZNT1 back-reference")
                token = chunk[idx] | (chunk[idx + 1] << 8)
                idx += 2

                # The length/displacement split depends on how far into the
                # chunk the copy target lies.
                cursor = len(out) - chunk_start - 1
                length_mask = 0x0FFF
                offset_shift = 12
                while cursor >= 0x10:
                    length_mask >>= 1
                    offset_shift -= 1
                    cursor >>= 1

                length = (token & length_mask) + 3
                displacement = (token >> offset_shift) + 1
                src = len(out) - displacement
                if src < chunk_start or src < 0:
                    raise ValueError("Invalid LZNT1 back-reference")
                # Overlapping copies are legal and must be byte-at-a-time.
                for _ in range(length):
                    out.append(out[src])
                    src += 1
                    if len(out) - chunk_start > 0x1000:
                        raise ValueError("LZNT1 chunk expands beyond 4096 bytes")

    return bytes(out)


class ZdmpFormatException(exceptions.LayerException):
    """Thrown when an error occurs parsing a ZDMP container."""


class ZdmpLayer(segmented.NonLinearlySegmentedLayer):
    """A Comae/MAGNET DumpIt compressed memory image."""

    HEADER_SIZE = 0x1000
    FILE_MAGIC = b"ZDMP"
    BLOCK_MAGIC = b"ZBLK"
    BLOCK_HEADER_SIZE = 12
    DATA_TYPE_COMPRESSION = 1
    COMPRESSION_LZNT1 = 2

    # Decompressed blocks retained in memory. Reads are overwhelmingly local --
    # walking a linked list or a page table touches the same block repeatedly --
    # so a small cache converts most reads into a dictionary hit. At the 2 MiB
    # block size DumpIt uses, 32 entries is roughly 64 MiB of process memory and
    # takes plugin runtimes from unusable to comparable with a converted image.
    CACHE_BLOCKS = 32

    def __init__(
        self,
        context: interfaces.context.ContextInterface,
        config_path: str,
        name: str,
        **kwargs,
    ) -> None:
        self._block_size = 0
        self._total_size = 0
        self._raw_blocks: set = set()
        self._checksums = {}
        self._cache = collections.OrderedDict()
        super().__init__(context, config_path, name, **kwargs)

    @classmethod
    def _parse_header(cls, base_layer, layer_name):
        header = base_layer.read(0, 24)
        if header[:4] != cls.FILE_MAGIC:
            raise ZdmpFormatException(
                layer_name, f"No ZDMP magic at offset 0: {header[:4]!r}"
            )
        _sig, version, total, block_size, data_type, compression = struct.unpack(
            "<IIQIHH", header
        )
        if data_type != cls.DATA_TYPE_COMPRESSION:
            raise ZdmpFormatException(
                layer_name,
                f"Unsupported ZDMP data type {data_type}; only 1 (compression) is known",
            )
        if compression != cls.COMPRESSION_LZNT1:
            raise ZdmpFormatException(
                layer_name,
                f"Unsupported ZDMP compression format {compression}; "
                "only 2 (LZNT1) is known",
            )
        if block_size == 0:
            raise ZdmpFormatException(layer_name, "ZDMP block size is zero")
        return version, total, block_size

    def _load_segments(self) -> None:
        base_layer = self._context.layers[self._base_layer]
        _version, total, block_size = self._parse_header(base_layer, self.name)
        self._block_size = block_size
        self._total_size = total

        segments = []
        offset = self.HEADER_SIZE  # position in the container
        decoded = 0  # position in the decompressed stream
        index = 0

        while decoded < total:
            try:
                block_header = base_layer.read(offset, self.BLOCK_HEADER_SIZE)
            except exceptions.InvalidAddressException as excp:
                raise ZdmpFormatException(
                    self.name,
                    f"Truncated ZDMP block header at container offset {offset:#x} "
                    f"after {index} blocks",
                ) from excp
            if len(block_header) < self.BLOCK_HEADER_SIZE:
                raise ZdmpFormatException(
                    self.name,
                    f"Truncated ZDMP block header at container offset {offset:#x} "
                    f"after {index} blocks",
                )
            if block_header[:4] != self.BLOCK_MAGIC:
                raise ZdmpFormatException(
                    self.name,
                    f"Bad ZBLK magic {block_header[:4]!r} at container offset "
                    f"{offset:#x} after {index} blocks",
                )
            compressed_size, checksum = struct.unpack("<II", block_header[4:12])
            if compressed_size == 0:
                raise ZdmpFormatException(
                    self.name,
                    f"ZDMP block at container offset {offset:#x} has an empty payload",
                )
            if compressed_size > block_size:
                raise ZdmpFormatException(
                    self.name,
                    f"ZDMP block at container offset {offset:#x} has payload size "
                    f"{compressed_size:#x}, larger than block size {block_size:#x}",
                )

            mapped_offset = offset + self.BLOCK_HEADER_SIZE
            if not base_layer.is_valid(mapped_offset, compressed_size):
                raise ZdmpFormatException(
                    self.name,
                    f"Truncated ZDMP block payload at container offset {mapped_offset:#x}: "
                    f"expected {compressed_size:#x} bytes",
                )
            self._checksums[mapped_offset] = checksum

            # Final block may be short.
            expanded = min(block_size, total - decoded)
            if compressed_size == block_size:
                # Stored verbatim: incompressible data.  DumpIt uses the full
                # container block size even when this is the logical final block.
                self._raw_blocks.add(mapped_offset)

            segments.append(
                (
                    decoded,
                    mapped_offset,
                    expanded,
                    compressed_size,
                )
            )
            offset += self.BLOCK_HEADER_SIZE + compressed_size
            decoded += expanded
            index += 1

        if not segments:
            raise ZdmpFormatException(self.name, "No ZBLK blocks found")
        if decoded != total:
            raise ZdmpFormatException(
                self.name,
                f"ZDMP block chain covers {decoded:#x} bytes, expected {total:#x}",
            )

        vollog.debug(
            "ZDMP: %d blocks, %d bytes decompressed, %d stored verbatim",
            len(segments),
            decoded,
            len(self._raw_blocks),
        )
        self._segments = segments

    def _expand_block(self, data: bytes, mapped_offset: int, expanded: int) -> bytes:
        """Return the fully decompressed, correctly sized contents of one block."""
        cached = self._cache.get(mapped_offset)
        if cached is not None:
            self._cache.move_to_end(mapped_offset)
            return cached

        expected_checksum = self._checksums.get(mapped_offset)
        if expected_checksum is not None:
            actual_checksum = binascii.crc32(data) & 0xFFFFFFFF
            if actual_checksum != expected_checksum:
                raise ZdmpFormatException(
                    self.name,
                    f"CRC32 mismatch for ZDMP block at container offset {mapped_offset:#x}: "
                    f"got {actual_checksum:#010x}, expected {expected_checksum:#010x}",
                )

        if mapped_offset in self._raw_blocks:
            decoded = data
        else:
            try:
                if _dissect_lznt1 is not None:
                    decoded = _dissect_lznt1.decompress(data)
                else:
                    decoded = lznt1_decompress(data)
            except (ValueError, EOFError, struct.error) as excp:
                raise ZdmpFormatException(
                    self.name,
                    f"Invalid LZNT1 data at container offset {mapped_offset:#x}",
                ) from excp
            if not decoded:
                raise ZdmpFormatException(
                    self.name,
                    f"LZNT1 block at container offset {mapped_offset:#x} "
                    "decompressed to zero bytes",
                )

        if len(decoded) > self._block_size:
            raise ZdmpFormatException(
                self.name,
                f"ZDMP block at container offset {mapped_offset:#x} decompressed to "
                f"{len(decoded):#x} bytes, larger than block size {self._block_size:#x}",
            )

        # Short blocks are zero padded. A logical final block may decode to the
        # full container block size, but only the header-declared bytes are exposed.
        if len(decoded) < expanded:
            decoded += b"\x00" * (expanded - len(decoded))
        elif len(decoded) > expanded:
            decoded = decoded[:expanded]

        self._cache[mapped_offset] = decoded
        if len(self._cache) > self.CACHE_BLOCKS:
            self._cache.popitem(last=False)
        return decoded

    def _decode_data(
        self, data: bytes, mapped_offset: int, offset: int, output_length: int
    ) -> bytes:
        start_offset, _, _, _ = self._find_segment(offset)
        expanded = min(self._block_size, self._total_size - start_offset)
        decoded = self._expand_block(data, mapped_offset, expanded)
        decoded = decoded[offset - start_offset :]
        return decoded[:output_length]


class ZdmpStacker(interfaces.automagic.StackerLayerInterface):
    stack_order = 10

    @classmethod
    def stack(
        cls,
        context: interfaces.context.ContextInterface,
        layer_name: str,
        progress_callback: constants.ProgressCallback = None,
    ) -> Optional[interfaces.layers.DataLayerInterface]:
        try:
            base = context.layers[layer_name]
            if base.read(0, 4) != ZdmpLayer.FILE_MAGIC:
                return None
        except exceptions.InvalidAddressException:
            return None

        new_name = context.layers.free_layer_name("ZdmpLayer")
        context.config[interfaces.configuration.path_join(new_name, "base_layer")] = (
            layer_name
        )
        try:
            layer = ZdmpLayer(context, new_name, new_name)
        except ZdmpFormatException as excp:
            vollog.log(constants.LOGLEVEL_VVV, "Not a ZDMP container: %s", excp)
            return None
        vollog.debug("Stacked %s on %s", new_name, layer_name)
        return layer
