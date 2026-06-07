# This file is Copyright 2026 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
"""Unit tests for the Windows automagic, focused on LA57 (5-level paging)
detection from the x64 Low Stub.

These build a synthetic _PROCESSOR_START_BLOCK inside a BufferDataLayer, so
no memory image is required.
"""

import struct

from volatility3.framework import constants, contexts
from volatility3.framework.automagic import windows
from volatility3.framework.layers import physical

STUB_OFFSET = 0x2000
CR3_VALUE = 0x1AD000
BUFFER_SIZE = 0x3000


def build_low_stub_buffer(cr4_value: int, *, stub: bool = True) -> bytes:
    """Builds a physical buffer optionally containing a valid x64 Low Stub."""
    buffer = bytearray(BUFFER_SIZE)
    if stub:
        buffer[STUB_OFFSET : STUB_OFFSET + 8] = struct.pack(
            "<Q", constants.windows.JMP_AND_COMPLETION_SIGNATURE
        )
        off = STUB_OFFSET + constants.windows.PROCESSOR_START_BLOCK_CR3_OFFSET
        buffer[off : off + 8] = struct.pack("<Q", CR3_VALUE)
        off = STUB_OFFSET + constants.windows.PROCESSOR_START_BLOCK_CR4_OFFSET
        buffer[off : off + 8] = struct.pack("<Q", cr4_value)
    return bytes(buffer)


def make_layer(cr4_value: int, *, stub: bool = True):
    context = contexts.Context()
    layer = physical.BufferDataLayer(
        context, "test.base", "base", build_low_stub_buffer(cr4_value, stub=stub)
    )
    context.add_layer(layer)
    return layer


class TestLa57FromLowStub:
    def test_la57_enabled(self):
        # CR4 with LA57 (bit 12) plus some unrelated bits set
        layer = make_layer(constants.windows.CR4_LA57_MASK | 0x170678)
        assert windows.WindowsIntelStacker._la57_from_low_stub(layer) is True

    def test_la57_disabled(self):
        # Typical 4-level CR4 (PAE, PGE, OSFXSR, ... but not LA57)
        layer = make_layer(0x170678)
        assert windows.WindowsIntelStacker._la57_from_low_stub(layer) is False

    def test_no_low_stub_returns_none(self):
        layer = make_layer(0, stub=False)
        assert windows.WindowsIntelStacker._la57_from_low_stub(layer) is None

    def test_matching_dtb_accepted(self):
        layer = make_layer(constants.windows.CR4_LA57_MASK)
        # page_map_offset agrees with the stub's CR3 (ignoring low 12 bits)
        assert (
            windows.WindowsIntelStacker._la57_from_low_stub(layer, CR3_VALUE) is True
        )

    def test_mismatching_dtb_rejected(self):
        layer = make_layer(constants.windows.CR4_LA57_MASK)
        # A Low Stub whose CR3 disagrees with the discovered DTB is ignored
        assert (
            windows.WindowsIntelStacker._la57_from_low_stub(layer, 0xDEAD000) is None
        )
