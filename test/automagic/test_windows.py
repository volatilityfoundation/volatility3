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
from volatility3.framework.layers import intel, physical

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


# --- End-to-end stacking through the real WindowsIntelStacker.stack() --------
#
# These build a complete synthetic physical image with both a self-referential
# DTB (so the DtbSelfRef64bit scan finds it) and an x64 Low Stub (so the
# LA57 refinement runs). A self-referential PML5 is byte-for-byte identical to
# a PML4, so the only thing that decides WindowsIntel32e vs WindowsIntel32e_LA57
# is CR4.LA57 from the Low Stub -- which is exactly what we exercise here.

# Place the DTB inside the first section the stacker scans, (0x150000, 0x150000).
STACK_DTB_OFFSET = 0x1A0000
STACK_STUB_OFFSET = 0x3000
# Cover the whole first section so _coalesce_sections trims the later (larger)
# sections cleanly instead of clipping this one.
STACK_IMAGE_SIZE = 0x2A1000
# Self-referential index, within DtbSelfRef64bit.valid_range == range(0x100, 0x1FF)
SELF_REF_INDEX = 0x1ED


def build_la57_physical_image(*, cr4_la57: bool, with_stub: bool = True) -> bytes:
    """Builds a synthetic Windows physical image with a self-referential x64
    DTB and (optionally) a Low Stub advertising LA57 via CR4."""
    buffer = bytearray(STACK_IMAGE_SIZE)

    # --- Self-referential top-level page table (PML4/PML5) at STACK_DTB_OFFSET
    def put_entry(index: int, value: int) -> None:
        off = STACK_DTB_OFFSET + index * 8
        buffer[off : off + 8] = struct.pack("<Q", value)

    # The one self-referential entry: (entry & 0x3FFFFFFFFFF000) == DTB, present.
    put_entry(SELF_REF_INDEX, STACK_DTB_OFFSET | 0x3)
    # A dozen ordinary present entries so the table is not flagged as a "dummy"
    # (the stacker requires >= 10 valid pointers). None set bit 7 (reserved) and
    # none alias the DTB offset.
    for i in range(12):
        put_entry(i, (0x10000 + i * 0x1000) | 0x3)

    # --- x64 Low Stub (_PROCESSOR_START_BLOCK) -----------------------------
    if with_stub:
        sig_off = STACK_STUB_OFFSET
        buffer[sig_off : sig_off + 8] = struct.pack(
            "<Q", constants.windows.JMP_AND_COMPLETION_SIGNATURE
        )
        cr3_off = STACK_STUB_OFFSET + constants.windows.PROCESSOR_START_BLOCK_CR3_OFFSET
        # CR3 must agree with the discovered DTB (low 12 bits ignored)
        buffer[cr3_off : cr3_off + 8] = struct.pack("<Q", STACK_DTB_OFFSET)
        cr4_off = STACK_STUB_OFFSET + constants.windows.PROCESSOR_START_BLOCK_CR4_OFFSET
        cr4_value = 0x170678  # typical 4-level CR4 bits
        if cr4_la57:
            cr4_value |= constants.windows.CR4_LA57_MASK
        buffer[cr4_off : cr4_off + 8] = struct.pack("<Q", cr4_value)

    return bytes(buffer)


def stack_la57_image(**kwargs):
    """Runs the real WindowsIntelStacker.stack() over a synthetic image and
    returns the constructed translation layer (or None)."""
    context = contexts.Context()
    layer = physical.BufferDataLayer(
        context, "test.base", "base", build_la57_physical_image(**kwargs)
    )
    context.add_layer(layer)
    return windows.WindowsIntelStacker.stack(context, "base")


class TestLa57Stacking:
    """End-to-end: the stacker must pick the LA57 layer iff CR4.LA57 is set."""

    def setup_method(self, _method):
        # Force the single-threaded scan path so a BufferDataLayer is not pickled
        # across a multiprocessing pool.
        self._saved_parallelism = constants.PARALLELISM
        constants.PARALLELISM = constants.Parallelism.Off

    def teardown_method(self, _method):
        constants.PARALLELISM = self._saved_parallelism

    def test_stacks_la57_layer_when_cr4_set(self):
        layer = stack_la57_image(cr4_la57=True)
        assert layer is not None
        assert type(layer) is intel.WindowsIntel32e_LA57

    def test_stacks_plain_64bit_when_cr4_clear(self):
        layer = stack_la57_image(cr4_la57=False)
        assert layer is not None
        # CR4.LA57 clear -> ordinary 4-level layer, not the LA57 subclass
        assert type(layer) is intel.WindowsIntel32e

    def test_stacks_plain_64bit_without_low_stub(self):
        # No Low Stub at all (e.g. a snapshot) -> fall back to 4-level
        layer = stack_la57_image(cr4_la57=True, with_stub=False)
        assert layer is not None
        assert type(layer) is intel.WindowsIntel32e
