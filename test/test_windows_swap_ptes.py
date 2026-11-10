"""Paged out (software) PTEs in the Windows Intel layers, on hand-built page tables.

Kernels whose _MMPTE_SOFTWARE has SwizzleBit keep the page file number at bit 12
rather than bit 1, and add InvalidPteMask to software PTEs whose SwizzleBit is
clear.  The layers take the layout and the mask from the kernel's symbols.
"""

import json
import struct

import pytest

from volatility3.framework import contexts, exceptions
from volatility3.framework.automagic import windows as windows_automagic
from volatility3.framework.configuration import requirements
from volatility3.framework.layers import intel, physical
from volatility3.framework.symbols import intermed

PAGE = 0x1000
PRESENT_RW_USER = 0x7
READWRITE, READONLY = 4, 1  # MM_READWRITE sets bit 7 of the PTE, MM_READONLY does not
MASK = 1 << 45  # InvalidPteMask as read from a Windows 10 19041 kernel
MASK_HIGH = MASK >> 32
NEW_LAYOUT = {"page_file_low_bit": 12, "swizzle_bit": 4, "invalid_pte_mask": MASK}

# (layer class, entry format, number of tables, PageFileHigh shift, large page size)
X64 = (intel.WindowsIntel32e, "<Q", 4, 32, 1 << 21)
PAE = (intel.WindowsIntelPAE, "<Q", 3, 32, 1 << 21)
X86 = (intel.WindowsIntel, "<I", 2, 12, 1 << 22)


def software_pte(high, number=0, protection=READWRITE, swizzle=0, low_bit=12):
    return high << 32 | number << low_bit | protection << 5 | swizzle << 4


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


@pytest.mark.parametrize("arch", [X64, PAE], ids=["x64", "pae"])
class TestSwizzledPtes:
    def test_the_mask_is_removed_when_the_swizzle_bit_is_clear(self, arch):
        layer = build(arch, software_pte(MASK_HIGH | 5), config=NEW_LAYOUT)
        assert layer._translate(PAGE) == (5 * PAGE, PAGE, "swap0")
        assert layer.read(PAGE, 8) == b"PF0:0005"

    def test_a_swizzled_demand_zero_pte_is_not_in_the_page_file(self, arch):
        """Before, PageFileHigh read 0x2000 and the page came from offset 0x2000000."""
        assert_not_swapped(build(arch, software_pte(MASK_HIGH), config=NEW_LAYOUT))

    def test_the_mask_is_kept_when_the_swizzle_bit_is_set(self, arch):
        entry = software_pte(MASK_HIGH | 5, swizzle=1)
        layer = build(arch, entry, config=NEW_LAYOUT)
        assert layer._translate(PAGE) == ((MASK_HIGH | 5) * PAGE, PAGE, "swap0")

    def test_the_page_file_number_is_read_at_page_file_low(self, arch):
        """Bits 1-4 now hold other flags, here PageFileReserved and PageFileAllocated."""
        entry = software_pte(3, number=1) | 0b0110
        layer = build(arch, entry, config=NEW_LAYOUT)
        assert layer._translate(PAGE) == (3 * PAGE, PAGE, "swap1")
        entry = software_pte(3, number=0) | 0b0110
        assert build(arch, entry, config=NEW_LAYOUT)._translate(PAGE)[2] == "swap0"

    def test_without_a_swap_layer_the_exception_has_the_unmasked_offset(self, arch):
        layer = build(arch, software_pte(MASK_HIGH | 5), config=NEW_LAYOUT, swap=False)
        with pytest.raises(exceptions.SwappedInvalidAddressException) as excp:
            layer._translate(PAGE)
        assert excp.value.swap_offset == 5 * PAGE

    def test_without_a_known_mask_a_pte_that_may_carry_it_is_not_read(self, arch):
        """If the mask could not be read, reads from offset 0x2000000 must not come back."""
        layout = {"page_file_low_bit": 12, "swizzle_bit": 4}
        assert_not_swapped(build(arch, software_pte(MASK_HIGH), config=layout))
        assert_not_swapped(build(arch, software_pte(5), config=layout))
        entry = software_pte(MASK_HIGH | 5, swizzle=1)
        expected = ((MASK_HIGH | 5) * PAGE, PAGE, "swap0")
        assert build(arch, entry, config=layout)._translate(PAGE) == expected

    def test_a_mask_of_zero_leaves_page_file_high_alone(self, arch):
        """CPUs that need no mask report 0."""
        layout = {**NEW_LAYOUT, "invalid_pte_mask": 0}
        expected = (5 * PAGE, PAGE, "swap0")
        assert build(arch, software_pte(5), config=layout)._translate(PAGE) == expected
        assert_not_swapped(build(arch, software_pte(0), config=layout))

    def test_without_the_kernel_layout_the_old_layout_is_used(self, arch):
        """Number at bit 1 and no mask, as for kernels without SwizzleBit."""
        entry = software_pte(MASK_HIGH | 5, number=1, low_bit=1)
        expected = ((MASK_HIGH | 5) * PAGE, PAGE, "swap1")
        assert build(arch, entry)._translate(PAGE) == expected


# A kernel without SwizzleBit: its layout is known, but there is no mask
OLD_LAYOUT = {"page_file_low_bit": 1}


@pytest.mark.parametrize("arch", [X64, PAE, X86], ids=["x64", "pae", "x86"])
class TestWhichEntriesArePagedOut:
    @staticmethod
    def high(arch, value):
        """Places PageFileHigh where this architecture keeps it."""
        return value << arch[3]

    def test_a_read_only_page_is_paged_out(self, arch):
        """Bit 7 is part of the protection, and MM_READONLY leaves it clear."""
        entry = self.high(arch, 5) | READONLY << 5
        layer = build(arch, entry, config=OLD_LAYOUT)
        assert layer._translate(PAGE) == (5 * PAGE, PAGE, "swap0")

    def test_a_read_inside_a_paged_out_page_starts_at_that_offset(self, arch):
        """Before, the offset inside the page was dropped and every read started at the slot."""
        layer = build(arch, self.high(arch, 5) | READWRITE << 5, config=OLD_LAYOUT)
        assert layer._translate(PAGE + 4) == (5 * PAGE + 4, PAGE, "swap0")
        assert layer.read(PAGE + 4, 4) == b"0005"

    def test_a_read_across_a_paged_out_page_continues_in_the_next_page(self, arch):
        entry = self.high(arch, 5) | READWRITE << 5
        layer = build(arch, entry, config=OLD_LAYOUT, pages={2: b"NEXT"})
        assert layer.read(2 * PAGE - 4, 8) == bytes(4) + b"NEXT"

    def test_without_the_kernel_layout_bit_7_is_still_required(self, arch):
        assert_not_swapped(build(arch, self.high(arch, 5) | READONLY << 5))
        entry = self.high(arch, 5) | READWRITE << 5
        assert build(arch, entry)._translate(PAGE)[2] == "swap0"

    def test_protection_zero_is_not_paged_out(self, arch):
        """The kernel's lists of free system PTEs look like this."""
        assert_not_swapped(build(arch, self.high(arch, 5), config=OLD_LAYOUT))

    def test_a_pte_that_needs_the_vad_is_not_paged_out(self, arch):
        all_ones = (1 << (struct.calcsize(arch[1]) * 8 - arch[3])) - 1
        entry = self.high(arch, all_ones) | READWRITE << 5
        assert_not_swapped(build(arch, entry, config=OLD_LAYOUT))
        assert_not_swapped(build(arch, entry))

    def test_a_paged_out_page_table_is_not_read_as_a_large_page(self, arch):
        """Before, this read a large page from the page file at PageFileHigh << 21 or 22."""
        for config in (None, OLD_LAYOUT):
            layer = build(arch, pde=self.high(arch, 5) | READWRITE << 5, config=config)
            assert_not_swapped(layer)
            assert_not_swapped(layer, arch[4] - PAGE)

    def test_a_read_only_paged_out_page_table_is_not_read(self, arch):
        """Bit 7 is clear here, so this goes through the protection test, not the large page path."""
        for config in (None, OLD_LAYOUT):
            layer = build(arch, pde=self.high(arch, 5) | READONLY << 5, config=config)
            assert_not_swapped(layer)
            assert_not_swapped(layer, arch[4] - PAGE)

    def test_a_page_file_without_a_layer_raises_swapped(self, arch):
        entry = self.high(arch, 5) | READWRITE << 5 | 2 << 1
        layer = build(arch, entry, config=OLD_LAYOUT)
        with pytest.raises(exceptions.SwappedInvalidAddressException) as excp:
            layer._translate(PAGE)
        assert excp.value.swap_offset == 5 * PAGE

    def test_a_demand_zero_pte_is_not_paged_out(self, arch):
        assert_not_swapped(build(arch, READWRITE << 5, config=OLD_LAYOUT))

    def test_transition_and_prototype_ptes_are_unchanged(self, arch):
        """A transition PTE still maps its frame, and a prototype PTE still faults."""
        data_frame = PAGE * (arch[2] + 1)
        layer = build(
            arch,
            pte=data_frame | 1 << 11 | READWRITE << 5,
            config=NEW_LAYOUT,
            pages={2: b"DATA"},
        )
        assert layer._translate(PAGE)[:2] == (data_frame, PAGE)
        assert layer.read(PAGE, 4) == b"DATA"
        assert_not_swapped(build(arch, self.high(arch, 5) | 1 << 10, config=NEW_LAYOUT))


def kernel_isf(tmp_path, with_swizzle, mask_at):
    """An ISF with the kernel's PTE layout and the InvalidPteMask in MiState, in the
    older global MiInvalidPteMask, or (None) in neither."""

    def bitfield(position, length):
        return {
            "kind": "bitfield",
            "bit_position": position,
            "bit_length": length,
            "type": {"kind": "base", "name": "unsigned long long"},
        }

    def field(offset, kind):
        return {"offset": offset, "type": kind}

    pte_fields = {
        "Valid": field(0, bitfield(0, 1)),
        "PageFileLow": field(0, bitfield(12, 4)),
        "PageFileHigh": field(0, bitfield(32, 32)),
    }
    if with_swizzle:
        pte_fields["SwizzleBit"] = field(0, bitfield(4, 1))
    integer = {"kind": "int", "size": 8, "signed": False, "endian": "little"}
    hardware_fields = {}
    if mask_at == "MiState":
        hardware_fields["InvalidPteMask"] = field(
            8, {"kind": "base", "name": "unsigned long long"}
        )
    symbols = {"MiState": {"address": 0x100}}
    if mask_at == "global":
        symbols = {"MiInvalidPteMask": {"address": 0x200}}
    isf = {
        "metadata": {
            "producer": {"name": "test", "version": "0", "datetime": "2026-11-07"},
            "format": "6.2.0",
        },
        "base_types": {"unsigned long long": integer, "pointer": integer},
        "user_types": {
            "_MMPTE_SOFTWARE": {"kind": "struct", "size": 8, "fields": pte_fields},
            "_MI_HARDWARE_STATE": {
                "kind": "struct",
                "size": 0x10,
                "fields": hardware_fields,
            },
            "_MI_SYSTEM_INFORMATION": {
                "kind": "struct",
                "size": 0x20,
                "fields": {
                    "Hardware": field(
                        0x10, {"kind": "struct", "name": "_MI_HARDWARE_STATE"}
                    )
                },
            },
        },
        "enums": {},
        "symbols": symbols,
    }
    path = tmp_path / "kernel.json"
    path.write_text(json.dumps(isf))
    return path.as_uri()


class TestLayoutFromTheKernel:
    """The automagic copies the kernel's layout and mask onto the layer."""

    @staticmethod
    def run_automagic(
        tmp_path, with_swizzle=True, mask_at="MiState", arch=X64, config=None, mask=MASK
    ):
        kernel_page = bytearray(PAGE)
        struct.pack_into("<Q", kernel_page, 0x100 + 0x10 + 8, mask)  # MiState
        struct.pack_into("<Q", kernel_page, 0x200, mask)  # MiInvalidPteMask
        layer = build(
            arch,
            config={"kernel_virtual_offset": 2 * PAGE, **(config or {})},
            pages={2: bytes(kernel_page)},
        )
        context = layer.context
        table = intermed.IntermediateSymbolTable(
            context,
            "test.symbols",
            "kernel",
            kernel_isf(tmp_path, with_swizzle, mask_at),
        )
        context.symbol_space.append(table)
        context.config["plugins.Test.kernel.layer_name"] = layer.name
        context.config["plugins.Test.kernel.symbol_table_name"] = "kernel"
        requirement = requirements.ModuleRequirement(
            name="kernel", architectures=["Intel64"]
        )
        magic = windows_automagic.WinSoftwarePteLayout(context, "automagic.Test")
        magic(context, "plugins.Test", requirement)
        return layer

    @staticmethod
    def settings(layer):
        return {key: layer.config.get(key) for key in NEW_LAYOUT}

    def test_the_layout_and_mask_are_set(self, tmp_path):
        assert self.settings(self.run_automagic(tmp_path)) == NEW_LAYOUT

    def test_the_mask_can_come_from_the_older_global_variable(self, tmp_path):
        layer = self.run_automagic(tmp_path, mask_at="global")
        assert self.settings(layer) == NEW_LAYOUT

    def test_without_a_readable_mask_only_the_layout_is_set(self, tmp_path):
        layer = self.run_automagic(tmp_path, mask_at=None)
        assert self.settings(layer) == {**NEW_LAYOUT, "invalid_pte_mask": None}

    def test_a_mask_outside_page_file_high_is_ignored(self, tmp_path):
        layer = self.run_automagic(tmp_path, mask=MASK | 0x10)
        assert self.settings(layer) == {**NEW_LAYOUT, "invalid_pte_mask": None}

    def test_a_mask_of_zero_is_kept(self, tmp_path):
        """A CPU that needs no mask reports 0, which is not the same as no mask."""
        layer = self.run_automagic(tmp_path, mask=0)
        assert self.settings(layer) == {**NEW_LAYOUT, "invalid_pte_mask": 0}

    def test_no_swizzle_bit_means_no_mask(self, tmp_path):
        layer = self.run_automagic(tmp_path, with_swizzle=False)
        expected = {"page_file_low_bit": 12, "swizzle_bit": None}
        assert self.settings(layer) == {**expected, "invalid_pte_mask": None}

    def test_values_already_set_are_kept(self, tmp_path):
        layer = self.run_automagic(tmp_path, config={"page_file_low_bit": 1})
        assert self.settings(layer) == {**NEW_LAYOUT, "page_file_low_bit": 1}

    def test_a_layer_without_a_kernel_offset_is_left_alone(self, tmp_path):
        layer = self.run_automagic(tmp_path, config={"kernel_virtual_offset": None})
        assert set(self.settings(layer).values()) == {None}

    def test_a_non_windows_layer_is_left_alone(self, tmp_path):
        layer = self.run_automagic(tmp_path, arch=(intel.Intel32e, *X64[1:]))
        assert set(self.settings(layer).values()) == {None}

    def test_the_settings_are_part_of_the_layer_configuration(self, tmp_path):
        """Process layers are built from this configuration, so they inherit them."""
        configuration = self.run_automagic(tmp_path).build_configuration()
        assert {key: configuration.get(key) for key in NEW_LAYOUT} == NEW_LAYOUT
