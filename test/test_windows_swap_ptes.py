"""Paged out (software) PTEs in the Windows Intel layers, on hand-built page tables."""

import struct

import pytest

from volatility3.framework import contexts, exceptions
from volatility3.framework.layers import intel, physical

PAGE = 0x1000
PRESENT_RW_USER = 0x7
READWRITE = 4  # MM_READWRITE, which sets bit 7 of the PTE

# (layer class, entry format, number of tables, PageFileHigh shift, large page size)
X64 = (intel.WindowsIntel32e, "<Q", 4, 32, 1 << 21)
PAE = (intel.WindowsIntelPAE, "<Q", 3, 32, 1 << 21)
X86 = (intel.WindowsIntel, "<I", 2, 12, 1 << 22)


def build(arch, pte=None, pde=None, config=None, swap=True, pages=None):
    """A layer whose first page table holds `pte` at index 1 (virtual address 0x1000).

    `pde` replaces the entry that points to that page table, and `pages` maps
    page table indexes to the contents of present pages.
    """
    cls, fmt, levels, _, _ = arch
    size = struct.calcsize(fmt)
    tables = [PAGE * (i + 1) for i in range(levels)]
    memory = bytearray(PAGE * (levels + 1))
    for upper, lower in zip(tables, tables[1:]):
        struct.pack_into(fmt, memory, upper, lower | PRESENT_RW_USER)
    if pde is not None:
        struct.pack_into(fmt, memory, tables[-2], pde)
    if pte is not None:
        struct.pack_into(fmt, memory, tables[-1] + size, pte)
    for index, content in (pages or {}).items():
        frame = len(memory)
        memory += content.ljust(PAGE, b"\0")
        struct.pack_into(
            fmt, memory, tables[-1] + index * size, frame | PRESENT_RW_USER
        )

    context = contexts.Context()
    context.add_layer(
        physical.BufferDataLayer(context, "test.memory", "memory", bytes(memory))
    )
    context.config["test.intel.memory_layer"] = "memory"
    context.config["test.intel.page_map_offset"] = tables[0]
    if swap:
        context.config["test.intel.swap_layers"] = True
        for number in range(2):
            name = f"swap{number}"
            content = b"".join(
                f"PF{number}:{slot:04x}".encode().ljust(PAGE, b"\0")
                for slot in range(16)
            )
            context.add_layer(
                physical.BufferDataLayer(context, f"test.{name}", name, content)
            )
            context.config[f"test.intel.swap_layers.swap_layers{number}"] = name
    for key, value in (config or {}).items():
        context.config[f"test.intel.{key}"] = value
    layer = cls(context, "test.intel", "intel")
    context.add_layer(layer)
    return layer


def assert_not_swapped(layer, address=PAGE):
    with pytest.raises(exceptions.PagedInvalidAddressException) as excp:
        layer._translate(address)
    assert not isinstance(excp.value, exceptions.SwappedInvalidAddressException)


@pytest.mark.parametrize("arch", [X64, PAE, X86], ids=["x64", "pae", "x86"])
class TestWhichEntriesArePagedOut:
    @staticmethod
    def high(arch, value):
        """Places PageFileHigh where this architecture keeps it."""
        return value << arch[3]

    def test_a_paged_out_pte_is_in_the_page_file(self, arch):
        entry = self.high(arch, 5) | READWRITE << 5
        assert build(arch, entry)._translate(PAGE) == (5 * PAGE, PAGE, "swap0")

    def test_a_pte_that_needs_the_vad_is_not_paged_out(self, arch):
        all_ones = (1 << (struct.calcsize(arch[1]) * 8 - arch[3])) - 1
        assert_not_swapped(build(arch, self.high(arch, all_ones) | READWRITE << 5))

    def test_a_paged_out_page_table_is_not_read_as_a_large_page(self, arch):
        """Before, this read a large page from the page file at PageFileHigh << 21 or 22."""
        layer = build(arch, pde=self.high(arch, 5) | READWRITE << 5)
        assert_not_swapped(layer)
        assert_not_swapped(layer, arch[4] - PAGE)

    def test_a_demand_zero_pte_is_not_paged_out(self, arch):
        assert_not_swapped(build(arch, READWRITE << 5))

    def test_transition_and_prototype_ptes_are_unchanged(self, arch):
        """A transition PTE still maps its frame, and a prototype PTE still faults."""
        data_frame = PAGE * (arch[2] + 1)
        layer = build(
            arch, pte=data_frame | 1 << 11 | READWRITE << 5, pages={2: b"DATA"}
        )
        assert layer._translate(PAGE)[:2] == (data_frame, PAGE)
        assert layer.read(PAGE, 4) == b"DATA"
        assert_not_swapped(build(arch, self.high(arch, 5) | 1 << 10))
