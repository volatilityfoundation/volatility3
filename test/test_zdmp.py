# This file is Copyright 2026 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0

import binascii
import struct

import pytest

from volatility3.framework import contexts, interfaces
from volatility3.framework.layers import physical
from volatility3.framework.layers.zdmp import (
    ZdmpFormatException,
    ZdmpLayer,
    ZdmpStacker,
    lznt1_decompress,
)


def _lznt1_literal(data: bytes) -> bytes:
    """Build one valid uncompressed LZNT1 chunk."""
    assert 0 < len(data) <= 0x1000
    header = 0x3000 | (len(data) - 1)
    return struct.pack("<H", header) + data


def _zdmp_header(
    total_size: int,
    block_size: int,
    data_type: int = 1,
    compression: int = 2,
) -> bytes:
    header = struct.pack(
        "<4sIQIHH",
        b"ZDMP",
        0x100,
        total_size,
        block_size,
        data_type,
        compression,
    )
    return header.ljust(ZdmpLayer.HEADER_SIZE, b"\x00")


def _block(payload: bytes, checksum=None) -> bytes:
    if checksum is None:
        checksum = binascii.crc32(payload) & 0xFFFFFFFF
    return b"ZBLK" + struct.pack("<II", len(payload), checksum) + payload


def _container(
    total_size: int,
    block_size: int,
    payloads,
    data_type: int = 1,
    compression: int = 2,
) -> bytes:
    return _zdmp_header(total_size, block_size, data_type, compression) + b"".join(
        _block(payload) for payload in payloads
    )


def _make_context(data: bytes):
    context = contexts.Context()
    base = physical.BufferDataLayer(context, "base", "base", data)
    context.add_layer(base)
    return context


def _make_layer(data: bytes) -> ZdmpLayer:
    context = _make_context(data)
    context.config[interfaces.configuration.path_join("zdmp", "base_layer")] = "base"
    layer = ZdmpLayer(context, "zdmp", "zdmp")
    context.add_layer(layer)
    return layer


def test_lznt1_uncompressed_chunk():
    assert lznt1_decompress(_lznt1_literal(b"hello")) == b"hello"


def test_lznt1_rejects_invalid_backreference():
    # Compressed chunk: first token is a back-reference before any output exists.
    malformed = struct.pack("<H", 0xB002) + b"\x01\x00\x00"
    with pytest.raises(ValueError, match="back-reference"):
        lznt1_decompress(malformed)


def test_lznt1_rejects_truncated_chunk():
    malformed = struct.pack("<H", 0x3004) + b"abc"
    with pytest.raises(ValueError, match="Truncated LZNT1 chunk"):
        lznt1_decompress(malformed)


def test_raw_block():
    payload = b"ABCDEFGH"
    layer = _make_layer(_container(8, 8, [payload]))
    assert layer.read(0, 8) == payload


def test_compressed_block_zero_pads_short_decode():
    payload = _lznt1_literal(b"hello")
    layer = _make_layer(_container(8, 8, [payload]))
    assert layer.read(0, 8) == b"hello\x00\x00\x00"


def test_compressed_block_rejects_decode_larger_than_block():
    # Literal "A" followed by an overlapping back-reference that expands to 19 bytes.
    payload = struct.pack("<H", 0xB003) + b"\x02A\x0f\x00"
    layer = _make_layer(_container(16, 16, [payload]))
    with pytest.raises(ZdmpFormatException, match="larger than block size"):
        layer.read(0, 16)


def test_short_final_block_is_logically_truncated():
    first = b"ABCDEFGH"
    # DumpIt's raw-block marker is a full-size payload even for a logical final block.
    final = b"IJxxxxxx"
    layer = _make_layer(_container(10, 8, [first, final]))
    assert layer.maximum_address == 9
    assert layer.read(0, 10) == b"ABCDEFGHIJ"


def test_bad_crc_is_rejected_on_read():
    payload = b"ABCDEFGH"
    data = _zdmp_header(8, 8) + _block(payload, checksum=0)
    layer = _make_layer(data)
    with pytest.raises(ZdmpFormatException, match="CRC32 mismatch"):
        layer.read(0, 8)


def test_truncated_block_payload_is_rejected():
    payload = b"ABCDEFG"
    checksum = binascii.crc32(payload) & 0xFFFFFFFF
    data = _zdmp_header(8, 8) + b"ZBLK" + struct.pack("<II", 8, checksum) + payload
    with pytest.raises(ZdmpFormatException, match="Truncated ZDMP block payload"):
        _make_layer(data)


def test_zero_sized_block_is_rejected():
    data = _zdmp_header(8, 8) + b"ZBLK" + struct.pack("<II", 0, 0)
    with pytest.raises(ZdmpFormatException, match="empty payload"):
        _make_layer(data)


def test_oversized_block_is_rejected():
    payload = b"A" * 9
    data = _zdmp_header(8, 8) + _block(payload)
    with pytest.raises(ZdmpFormatException, match="larger than block size"):
        _make_layer(data)


def test_unsupported_data_type_is_rejected():
    data = _container(8, 8, [b"ABCDEFGH"], data_type=2)
    with pytest.raises(ZdmpFormatException, match="Unsupported ZDMP data type"):
        _make_layer(data)


def test_unsupported_compression_is_rejected():
    data = _container(8, 8, [b"ABCDEFGH"], compression=99)
    with pytest.raises(
        ZdmpFormatException, match="Unsupported ZDMP compression format"
    ):
        _make_layer(data)


def test_stacker_detects_zdmp():
    context = _make_context(_container(8, 8, [b"ABCDEFGH"]))
    layer = ZdmpStacker.stack(context, "base")
    assert isinstance(layer, ZdmpLayer)
    assert layer.read(0, 8) == b"ABCDEFGH"


def test_stacker_ignores_non_zdmp():
    context = _make_context(b"not a zdmp container")
    assert ZdmpStacker.stack(context, "base") is None
