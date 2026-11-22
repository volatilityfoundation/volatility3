"""A large page over a layer that does not hold every page of it.

A hibernation file does not store every 4 KB page of the 2 MB pages Windows maps the
kernel with. Intel.mapping() skipped such a large page whole, so scans never saw the
kernel image and the PDB scan found no kernel.
"""

import struct

import pytest

from volatility3.framework import contexts, exceptions
from volatility3.framework.layers import intel, physical, scanners, segmented

PML4, PDPT, PD = 0x1000, 0x2000, 0x3000
PRESENT_RW_USER = 0x7
PS = 1 << 7
PAGE = 0x1000


class Sparse(segmented.SegmentedLayer):
    """A layer that lacks one page: a segment before the hole and one after it"""

    hole = 0

    def _load_segments(self):
        size = self.context.layers[self._base_layer].maximum_address + 1
        after = self.hole + PAGE
        self._segments = [(0, 0, min(self.hole, size), min(self.hole, size))]
        if after < size:
            self._segments.append((after, after, size - after, size - after))


def large_page(hole):
    """Virtual 0x200000-0x3FFFFF mapped by one 2 MB page to physical 0x200000, over a
    layer that lacks the page at `hole`; a marker sits at physical 0x2F0000."""
    memory = bytearray(0x400000)
    struct.pack_into("<Q", memory, PML4, PDPT | PRESENT_RW_USER)
    struct.pack_into("<Q", memory, PDPT, PD | PRESENT_RW_USER)
    struct.pack_into("<Q", memory, PD + 8, 0x200000 | PRESENT_RW_USER | PS)
    memory[0x2F0000 : 0x2F0000 + 8] = b"KERNELPD"
    context = contexts.Context()
    context.add_layer(
        physical.BufferDataLayer(context, "test.buffer", "buffer", bytes(memory))
    )
    context.config["test.memory.base_layer"] = "buffer"
    Sparse.hole = hole
    context.add_layer(Sparse(context, "test.memory", "memory_layer"))
    context.config["test.intel.memory_layer"] = "memory_layer"
    context.config["test.intel.page_map_offset"] = PML4
    layer = intel.WindowsIntel32e(context, "test.intel", "intel")
    context.add_layer(layer)
    return layer


def test_mapping_gives_the_valid_pieces():
    layer = large_page(hole=0x280000)
    pieces = [
        (offset, size, mapped)
        for offset, size, mapped, _, _ in layer.mapping(
            0x200000, 0x200000, ignore_errors=True
        )
    ]
    assert pieces == [
        (0x200000, 0x80000, 0x200000),
        (0x281000, 0x17F000, 0x281000),
    ]


def test_scan_finds_data_after_the_missing_page():
    layer = large_page(hole=0x280000)
    hits = list(
        layer.scan(
            layer.context,
            scanners.BytesScanner(b"KERNELPD"),
            sections=[(0x200000, 0x200000)],
        )
    )
    assert hits == [0x2F0000]


def test_a_whole_large_page_is_still_one_piece():
    layer = large_page(hole=0x400000)  # the hole is past the page
    assert [
        (offset, size)
        for offset, size, _, _, _ in layer.mapping(
            0x200000, 0x200000, ignore_errors=True
        )
    ] == [(0x200000, 0x200000)]


def test_strict_mapping_still_raises():
    layer = large_page(hole=0x280000)
    with pytest.raises(exceptions.InvalidAddressException):
        list(layer.mapping(0x200000, 0x200000))
