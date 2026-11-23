"""AVML segments whose snappy frames are stored uncompressed must load."""

import contextlib
import os
import signal
import struct
from typing import Tuple

import pytest

from volatility3.framework import contexts, exceptions
from volatility3.framework.layers import avml, physical

CHUNK = 0x10000
STREAM_IDENTIFIER = b"\xff\x06\x00\x00sNaPpY"


def _frame(frame_type: int, body: bytes) -> bytes:
    payload = b"\x00\x00\x00\x00" + body
    return struct.pack("<L", frame_type | (len(payload) << 8)) + payload


def _snappy_repeated_byte(value: int, length: int) -> bytes:
    out = bytearray()
    n = length
    while n >= 0x80:
        out.append((n & 0x7F) | 0x80)
        n >>= 7
    out.append(n)
    out += bytes([0x00, value])
    remaining = length - 1
    while remaining:
        step = min(64, remaining)
        out += bytes([((step - 1) << 2) | 0x02, 0x01, 0x00])
        remaining -= step
    return bytes(out)


def _avml_segment(start: int, data: bytes, frames: bytes) -> bytes:
    stream = STREAM_IDENTIFIER + frames
    header = struct.pack("<IIQQQ", 0x4C4D5641, 2, start, start + len(data) - 1, 0)
    return header + stream + struct.pack("<Q", len(stream))


def _uncompressed_frames(data: bytes) -> bytes:
    return b"".join(
        _frame(0x01, data[i : i + CHUNK]) for i in range(0, len(data), CHUNK)
    )


def _compressed_segment(start: int) -> Tuple[bytes, bytes]:
    data = b"A" * (2 * CHUNK)
    frames = b"".join(
        _frame(0x00, _snappy_repeated_byte(0x41, CHUNK)) for _ in range(2)
    )
    return data, _avml_segment(start, data, frames)


@contextlib.contextmanager
def _deadline(seconds: int):
    if not hasattr(signal, "SIGALRM"):
        yield
        return

    def _timeout(signum, frame):
        raise TimeoutError("AVML layer construction did not terminate")

    previous = signal.signal(signal.SIGALRM, _timeout)
    signal.alarm(seconds)
    try:
        yield
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, previous)


def _load(image: bytes) -> avml.AVMLLayer:
    context = contexts.Context()
    context.layers.add_layer(physical.BufferDataLayer(context, "base", "base", image))
    context.config["avml.base_layer"] = "base"
    with _deadline(10):
        return avml.AVMLLayer(context, "avml", "avml")


@pytest.mark.skipif(not avml.HAS_SNAPPY, reason="snappy library not available")
def test_compressed_segment():
    """Read back a segment stored as compressed snappy frames."""
    data, segment = _compressed_segment(0x1000)
    layer = _load(segment)
    assert layer.read(0x1000, len(data)) == data


@pytest.mark.parametrize("size", [1, 3 * CHUNK, 3 * CHUNK + 1])
def test_uncompressed_segment_after_compressed_segment(size):
    """Load a segment whose frames snappy stored uncompressed."""
    compressed_start = 0x1000
    compressed_data, compressed_segment = _compressed_segment(compressed_start)
    random_start = 0x100000
    random_data = os.urandom(size)

    layer = _load(
        compressed_segment
        + _avml_segment(random_start, random_data, _uncompressed_frames(random_data))
    )

    if avml.HAS_SNAPPY:
        assert layer.read(compressed_start, len(compressed_data)) == compressed_data
    assert layer.read(random_start, len(random_data)) == random_data
    if size > CHUNK:
        assert (
            layer.read(random_start + CHUNK - 16, 32)
            == random_data[CHUNK - 16 : CHUNK + 16]
        )


def test_truncated_segment_raises():
    """Raise on a segment whose snappy stream ends early."""
    random_data = os.urandom(2 * CHUNK)
    segment = _avml_segment(0x1000, random_data, _uncompressed_frames(random_data))
    with pytest.raises(exceptions.LayerException):
        _load(segment[:-CHUNK])
