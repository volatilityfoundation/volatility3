# This file is Copyright 2026 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
"""Unit tests for the Intel translation layers, with a focus on 5-level
paging (LA57).

These tests build synthetic page tables inside a BufferDataLayer, so no
memory image is required.  They cover:

- The full 5-level translation walk (4K, 2M and 1G pages)
- Canonicalization / decanonicalization of 57-bit addresses
- The address_mask regression that broke virtual pointer following
  (pslist failing while psscan worked) on LA57 images
- Windows transition / swapped page table entries on the LA57 layer
- Linux PROT_NONE PFN inversion on the LA57 layer
"""

import struct

import pytest

from volatility3.framework import contexts, exceptions
from volatility3.framework.layers import intel, physical

# Physical layout of the synthetic image
PML5_OFFSET = 0x1000
PML4_OFFSET = 0x2000
PDPT_OFFSET = 0x3000
PD_OFFSET = 0x4000
PT_OFFSET = 0x5000
DATA_OFFSET = 0x6000
BUFFER_SIZE = 0x10000

DATA_CONTENTS = b"LA57 5-level paging test page!!\x00" * (0x1000 // 32)

# Table indices used by the synthetic mappings (all non-zero, all distinct,
# so no table trips the duplicate-entry heuristic in _get_valid_table)
I5, I4, I3, I2, I1 = 0x1A, 0x2B, 0x3C, 0x4D, 0x5E
I5_HIGH = 0x1A0  # bit 8 set -> high (kernel) half of the 57-bit space
I3_1G = 0x3D  # 1G large page entry in the PDPT
I2_2M = 0x4E  # 2M large page entry in the PD
I1_FAULT = 0x5F  # PT entry left as zero -> page fault
I1_TRANS = 0x60  # Windows: PTE in transition state
I1_SWAP = 0x61  # Windows: swapped-out PTE
I1_PROT = 0x62  # Linux: PROT_NONE (inverted PFN) PTE

PHYS_2M = 0x800000  # 2M-aligned, intentionally outside the buffer
PHYS_1G = 0x40000000  # 1G-aligned, intentionally outside the buffer

ENTRY_FLAGS = 0x3  # present | writable
LARGE_FLAGS = 0x83  # present | writable | PSE


def make_va(i5: int, i4: int, i3: int, i2: int, i1: int, offset: int) -> int:
    """Builds a (decanonicalized) 57-bit virtual address from table indices."""
    return (i5 << 48) | (i4 << 39) | (i3 << 30) | (i2 << 21) | (i1 << 12) | offset


VA_4K = make_va(I5, I4, I3, I2, I1, 0x123)
VA_HIGH = make_va(I5_HIGH, I4, I3, I2, I1, 0x123)
VA_1G = make_va(I5, I4, I3_1G, 0, 0, 0) | 0x1234567
VA_2M = make_va(I5, I4, I3, I2_2M, 0, 0) | 0x12345
VA_FAULT = make_va(I5, I4, I3, I2, I1_FAULT, 0)
VA_TRANS = make_va(I5, I4, I3, I2, I1_TRANS, 0x123)
VA_SWAP = make_va(I5, I4, I3, I2, I1_SWAP, 0)
VA_PROT = make_va(I5, I4, I3, I2, I1_PROT, 0x123)

SWAP_PAGE_NUMBER = 0x1234


def build_la57_buffer(layer_class) -> bytes:
    """Builds a synthetic physical memory buffer containing 5-level page
    tables rooted at PML5_OFFSET."""
    buffer = bytearray(BUFFER_SIZE)

    def set_entry(table_offset: int, index: int, value: int) -> None:
        buffer[table_offset + index * 8 : table_offset + (index + 1) * 8] = (
            struct.pack("<Q", value)
        )

    # 5-level chain for VA_4K (and VA_HIGH, which shares everything below PML5)
    set_entry(PML5_OFFSET, I5, PML4_OFFSET | ENTRY_FLAGS)
    set_entry(PML5_OFFSET, I5_HIGH, PML4_OFFSET | ENTRY_FLAGS)
    set_entry(PML4_OFFSET, I4, PDPT_OFFSET | ENTRY_FLAGS)
    set_entry(PDPT_OFFSET, I3, PD_OFFSET | ENTRY_FLAGS)
    set_entry(PD_OFFSET, I2, PT_OFFSET | ENTRY_FLAGS)
    set_entry(PT_OFFSET, I1, DATA_OFFSET | ENTRY_FLAGS)

    # Large pages
    set_entry(PDPT_OFFSET, I3_1G, PHYS_1G | LARGE_FLAGS)
    set_entry(PD_OFFSET, I2_2M, PHYS_2M | LARGE_FLAGS)

    # Windows: transition PTE (bit 11 set, present and prototype clear)
    set_entry(PT_OFFSET, I1_TRANS, DATA_OFFSET | (1 << 11))
    # Windows: swapped PTE (only bit 7 set among the flag bits, swap offset
    # stored above bit 32 for 64-bit layers)
    set_entry(PT_OFFSET, I1_SWAP, (SWAP_PAGE_NUMBER << 32) | (1 << 7))

    # Linux: PROT_NONE PTE with inverted PFN (bit 8 set, present clear)
    if issubclass(layer_class, intel.LinuxMixin):
        pfn_mask = ((1 << layer_class._maxphyaddr) - 1) & ~0xFFF
        set_entry(PT_OFFSET, I1_PROT, (~DATA_OFFSET & pfn_mask) | (1 << 8))

    # The data page itself
    buffer[DATA_OFFSET : DATA_OFFSET + 0x1000] = DATA_CONTENTS
    return bytes(buffer)


def build_layer(layer_class) -> intel.Intel:
    """Creates a context with a synthetic physical layer and stacks the
    requested Intel layer class on top of it."""
    context = contexts.Context()
    base_name = "base_layer"
    base_layer = physical.BufferDataLayer(
        context, "test.base", base_name, build_la57_buffer(layer_class)
    )
    context.add_layer(base_layer)

    config_path = "test.intel"
    context.config[f"{config_path}.memory_layer"] = base_name
    context.config[f"{config_path}.page_map_offset"] = PML5_OFFSET
    layer = layer_class(context, config_path, "intel_layer")
    context.add_layer(layer)
    return layer


class TestIntel32eLA57Constants:
    def test_class_constants(self):
        assert intel.Intel32e_LA57._maxvirtaddr == 57
        assert len(intel.Intel32e_LA57._structure) == 5
        assert intel.Intel32e_LA57.maximum_address == (1 << 57) - 1
        # Plugins require Intel32/Intel64 architectures; LA57 must stay Intel64
        assert intel.Intel32e_LA57._direct_metadata["architecture"] == "Intel64"

    def test_address_mask_covers_57_bits(self):
        layer = build_layer(intel.Intel32e_LA57)
        assert layer.address_mask == (1 << 57) - 1

    def test_4level_address_mask_unchanged(self):
        """Regression: the 4-level layer must keep its 48-bit mask."""
        assert intel.Intel32e.maximum_address == (1 << 48) - 1


class TestIntel32eLA57Translation:
    def test_4k_page_translation(self):
        layer = build_layer(intel.Intel32e_LA57)
        mapped_offset, size, layer_name = layer._translate(VA_4K)
        assert mapped_offset == DATA_OFFSET | 0x123
        assert size == 0x1000
        assert layer_name == "base_layer"

    def test_4k_page_read(self):
        layer = build_layer(intel.Intel32e_LA57)
        assert layer.read(VA_4K & ~0xFFF, 0x1000) == DATA_CONTENTS

    def test_high_half_canonical_address(self):
        """A sign-extended (canonical) kernel address must translate to the
        same physical page as its decanonicalized form."""
        layer = build_layer(intel.Intel32e_LA57)
        canonical_va = layer.canonicalize(VA_HIGH)
        assert canonical_va >> 57 != 0  # really sign-extended
        mapped_offset, _, _ = layer._translate(canonical_va)
        assert mapped_offset == DATA_OFFSET | 0x123

    def test_2m_large_page(self):
        layer = build_layer(intel.Intel32e_LA57)
        mapped_offset, size, _ = layer._translate(VA_2M)
        assert mapped_offset == PHYS_2M | 0x12345
        assert size == 1 << 21

    def test_1g_large_page(self):
        layer = build_layer(intel.Intel32e_LA57)
        mapped_offset, size, _ = layer._translate(VA_1G)
        assert mapped_offset == PHYS_1G | 0x1234567
        assert size == 1 << 30

    def test_page_fault(self):
        layer = build_layer(intel.Intel32e_LA57)
        with pytest.raises(exceptions.PagedInvalidAddressException) as excinfo:
            layer.read(VA_FAULT, 1)
        assert excinfo.value.invalid_bits == 12

    def test_mapping_skips_invalid_pages(self):
        layer = build_layer(intel.Intel32e_LA57)
        page_va = VA_4K & ~0xFFF
        # Two pages: the faulting one and the valid one right after it
        mappings = list(layer.mapping(page_va - 0x1000, 0x2000, ignore_errors=True))
        assert mappings == [(page_va, 0x1000, DATA_OFFSET, 0x1000, "base_layer")]

    def test_non_canonical_address_is_masked(self):
        """The framework deliberately masks addresses with address_mask
        rather than rejecting non-canonical ones (matching the 4-level
        layers and the Pointer masking in objects/__init__.py), so a
        non-canonical address translates as its masked equivalent."""
        layer = build_layer(intel.Intel32e_LA57)
        # Bit 62 set but bit 56 clear: non-canonical under LA57
        mapped_offset, _, _ = layer._translate((1 << 62) | VA_4K)
        assert mapped_offset == DATA_OFFSET | 0x123


class TestIntel32eLA57Canonicalization:
    def test_canonicalize_boundaries(self):
        layer = build_layer(intel.Intel32e_LA57)
        # Highest low-half address is untouched
        assert layer.canonicalize((1 << 56) - 1) == (1 << 56) - 1
        # First high-half address gets sign-extended from bit 56
        assert layer.canonicalize(1 << 56) == 0xFF00000000000000
        assert layer.decanonicalize(0xFF00000000000000) == 1 << 56
        assert layer.decanonicalize((1 << 56) - 1) == (1 << 56) - 1

    def test_canonicalize_roundtrip(self):
        layer = build_layer(intel.Intel32e_LA57)
        for addr in ((1 << 56) | 0x1234, (1 << 57) - 1, 0x123456789A, 0):
            assert layer.decanonicalize(layer.canonicalize(addr)) == addr

    def test_pointer_masking_preserves_la57_pointers(self):
        """The original bug: 57-bit canonical kernel pointers were truncated
        to 48 bits by address_mask during pointer dereference
        (objects/__init__.py), so list walking (pslist) broke while physical
        scanning (psscan) kept working."""
        kernel_ptr = 0xFF91800000001234  # canonical 57-bit kernel pointer

        la57 = build_layer(intel.Intel32e_LA57)
        masked = kernel_ptr & la57.address_mask
        # Masking must be equivalent to decanonicalization: no information loss
        assert masked == la57.decanonicalize(kernel_ptr)
        assert la57.canonicalize(masked) == kernel_ptr

        # The same pointer through the 4-level mask is destroyed, which
        # documents why the bug only manifests on LA57 images
        mask_48 = (1 << 48) - 1
        assert ((kernel_ptr & mask_48) | (0xFFFF << 48)) != kernel_ptr


class TestWindowsIntel32eLA57:
    def test_transition_page_is_valid(self):
        """A PTE in transition state (bit 11 set, prototype clear) must
        still translate on the LA57 layer."""
        layer = build_layer(intel.WindowsIntel32e_LA57)
        mapped_offset, _, _ = layer._translate(VA_TRANS)
        assert mapped_offset == DATA_OFFSET | 0x123

    def test_swapped_page_raises_swap_exception(self):
        layer = build_layer(intel.WindowsIntel32e_LA57)
        with pytest.raises(exceptions.SwappedInvalidAddressException) as excinfo:
            layer.read(VA_SWAP, 1)
        assert excinfo.value.swap_offset == SWAP_PAGE_NUMBER << 12

    def test_4k_page_read(self):
        layer = build_layer(intel.WindowsIntel32e_LA57)
        assert layer.read(VA_4K & ~0xFFF, 0x1000) == DATA_CONTENTS


class TestLinuxIntel32eLA57:
    def test_maxphyaddr_is_52_bits(self):
        """5-level kernels always use a 52-bit __PHYSICAL_MASK_SHIFT."""
        assert intel.LinuxIntel32e_LA57._maxphyaddr == 52

    def test_protnone_inverted_pfn(self):
        """A PROT_NONE PTE stores its PFN inverted (L1TF mitigation); the
        LinuxMixin must recover the original PFN on the LA57 layer."""
        layer = build_layer(intel.LinuxIntel32e_LA57)
        mapped_offset, _, _ = layer._translate(VA_PROT)
        assert mapped_offset == DATA_OFFSET | 0x123

    def test_4k_page_read(self):
        layer = build_layer(intel.LinuxIntel32e_LA57)
        assert layer.read(VA_4K & ~0xFFF, 0x1000) == DATA_CONTENTS
