"""Large-page handling in the Intel layers, on hand-built page tables.

Bit 7 of a page-directory-pointer or page-directory entry means "this maps a
large page" only when the entry is present (bit 0).  Windows keeps entries in
the transition state (bit 11 set, bit 10 clear, bit 0 clear) for page tables
that are no longer mapped but still in RAM, and in that state bits 5 to 9 hold
the page protection, so bit 7 can be set by chance.  Volatility's Windows layer
accepts transition entries as valid, and used to read their bit 7 as a large
page: it then translated through a "1 GB page" whose frame was really the
next page table, and its scanner and its read() disagreed about where that
fake page's bytes were.  Upstream pull request 518 describes the same defect.
"""

import struct

import pytest

from volatility3.framework import contexts, exceptions
from volatility3.framework.layers import intel, physical, scanners

PML4, PDPT, PD, PT, DATA = 0x1000, 0x2000, 0x3000, 0x4000, 0x5000
PRESENT_RW_USER = 0x7
TRANSITION = 1 << 11
PS = 1 << 7
ONE_GB = 1 << 30


def build(pdpt_entries, pd_entry=PT | PRESENT_RW_USER, cls=intel.WindowsIntel32e):
    """An Intel 64-bit layer over a 32 KB buffer with the given PDPT entries (index -> value)."""
    memory = bytearray(0x8000)

    def put(table, index, value):
        struct.pack_into("<Q", memory, table + 8 * index, value)

    put(PML4, 0, PDPT | PRESENT_RW_USER)
    for index, value in pdpt_entries.items():
        put(PDPT, index, value)
    put(PD, 0, pd_entry)
    put(PT, 0, DATA | PRESENT_RW_USER)
    memory[DATA : DATA + 4] = b"REAL"
    # An unrelated byte pattern where a fake large page built from the PD's address lands: bit 12
    # of a large-page entry is the PAT bit, not part of the frame, so 0x3000 becomes 0x2000
    memory[PDPT + 0x800 : PDPT + 0x804] = b"FAKE"

    context = contexts.Context()
    context.add_layer(
        physical.BufferDataLayer(context, "test.memory", "memory_layer", bytes(memory))
    )
    context.config["test.intel.memory_layer"] = "memory_layer"
    context.config["test.intel.page_map_offset"] = PML4
    layer = cls(context, "test.intel", "intel")
    context.add_layer(layer)
    return layer


class TestTransitionEntryIsNotALargePage:
    def test_walk_continues_through_a_transition_entry_with_bit_7_set(self):
        """The defect: this entry was read as a 1 GB page starting at the page directory."""
        layer = build({1: PD | TRANSITION | PS | 0x4})
        physical_address, page_size, _ = layer._translate(ONE_GB)
        assert (physical_address, page_size) == (DATA, 0x1000)
        assert layer.read(ONE_GB, 4) == b"REAL"

    def test_scanner_and_read_agree(self):
        """With the defect, scan() reported addresses whose bytes read() could not confirm."""
        layer = build({1: PD | TRANSITION | PS | 0x4})
        hits = list(
            layer.scan(
                layer.context,
                scanners.BytesScanner(b"REAL"),
                sections=[(ONE_GB, 0x1000)],
            )
        )
        assert hits == [ONE_GB]
        assert all(layer.read(h, 4) == b"REAL" for h in hits)
        fakes = list(
            layer.scan(
                layer.context,
                scanners.BytesScanner(b"FAKE"),
                sections=[(ONE_GB, 0x200000)],
            )
        )
        assert fakes == []

    def test_a_transition_entry_without_bit_7_was_always_fine(self):
        layer = build({1: PD | TRANSITION | 0x4})
        assert layer._translate(ONE_GB)[0] == DATA


class TestRealLargePagesStillWork:
    def test_a_present_entry_with_bit_7_is_a_1gb_page(self):
        layer = build({2: (2 * ONE_GB) | PRESENT_RW_USER | PS})
        physical_address, page_size, _ = layer._translate(2 * ONE_GB + 0x1234)
        assert (physical_address, page_size) == (2 * ONE_GB + 0x1234, ONE_GB)

    def test_a_linux_prot_none_huge_page_is_still_a_2mb_page(self):
        """Linux clears the present bit of PROT_NONE huge pages and inverts their frame bits; the
        Windows-only rule must not touch that."""
        two_mb = 2 * 1024 * 1024
        frame = 0x40000000  # a 2 MB-aligned physical address
        pfn_mask = ((1 << intel.LinuxIntel32e._maxphyaddr) - 1) & ~0xFFF
        prot_none_huge = ((~frame) & pfn_mask) | (1 << 8) | PS | 0x4
        layer = build(
            {1: PD | PRESENT_RW_USER}, pd_entry=prot_none_huge, cls=intel.LinuxIntel32e
        )
        # Only what the Windows-only changes must preserve: still a 2 MB page, and no new fault.
        # (The address itself is not asserted: Volatility recovers PROT_NONE huge-page frames
        # with a 4 KB mask, a separate, Linux-only matter.)
        assert layer._translate(ONE_GB + 0x1234)[1] == two_mb

    def test_a_non_present_entry_that_is_not_in_transition_is_a_fault(self):
        layer = build({1: PD | PS | 0x4})
        with pytest.raises(exceptions.PagedInvalidAddressException):
            layer._translate(ONE_GB)


class TestMisalignedLargePageIsAFault:
    """A large page's frame must be aligned to the page's size: the CPU treats the low frame
    bits of a 2 MB or 1 GB entry as reserved and faults if any is set.  Such entries appear when
    a page that once held page tables is reached through a stale entry and now holds other data;
    translating through them made scan() and read() disagree, as OR and addition differ there."""

    @pytest.mark.parametrize(
        "pdpt, pd",
        [
            (
                {1: PD | PRESENT_RW_USER | PS},
                PT | PRESENT_RW_USER,
            ),  # 1 GB frame at 0x3000
            (
                {1: PD | PRESENT_RW_USER},
                0x10000 | PRESENT_RW_USER | PS,
            ),  # 2 MB frame at 0x10000
        ],
    )
    def test_a_misaligned_large_frame_is_a_fault(self, pdpt, pd):
        layer = build(pdpt, pd_entry=pd)
        with pytest.raises(exceptions.PagedInvalidAddressException):
            layer._translate(ONE_GB + 0x1234)

    def test_scanning_a_misaligned_large_page_finds_nothing(self):
        layer = build({1: PD | PRESENT_RW_USER | PS})
        fakes = list(
            layer.scan(
                layer.context,
                scanners.BytesScanner(b"FAKE"),
                sections=[
                    (ONE_GB, 0x1000)
                ],  # small enough that the fake page lies in the buffer
            )
        )
        assert fakes == []

    def test_an_aligned_2mb_page_still_translates(self):
        layer = build(
            {1: PD | PRESENT_RW_USER}, pd_entry=0x200000 | PRESENT_RW_USER | PS
        )
        assert layer._translate(ONE_GB + 0x1234)[:2] == (0x200000 + 0x1234, 0x200000)
