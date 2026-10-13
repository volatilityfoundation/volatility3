# This file is Copyright 2026 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
"""Unit tests for the Linux automagic, focused on LA57 (5-level paging)
detection in the Linux stackers.

These build synthetic page tables inside a BufferDataLayer, so no memory
image or ISF is required.
"""

import struct
from typing import Optional

import pytest

from volatility3.framework import contexts
from volatility3.framework.automagic import linux
from volatility3.framework.layers import intel, physical

KERNEL_TEXT_BASE = 0xFFFFFFFF80000000
DTB_OFFSET = 0x1000
TABLES_OFFSET = 0x2000
BUFFER_SIZE = 0x10000
# Virtual address of the top-level page table (init_top_pgt) in kernel text
DTB_VADDR = KERNEL_TEXT_BASE + DTB_OFFSET

CONFIG_PATH = "test.intel"
LAYER_NAME = "intel_layer"


def build_image(levels: Optional[int]) -> bytes:
    """Builds a physical image whose top-level table at DTB_OFFSET maps its
    own kernel text address back to itself, using the given number of paging
    levels (4K pages, no KASLR).  levels=None leaves the table unmapped."""
    buffer = bytearray(BUFFER_SIZE)
    if levels:
        shifts = [48, 39, 30, 21, 12][5 - levels :]
        table = DTB_OFFSET
        for level, shift in enumerate(shifts):
            if level == len(shifts) - 1:
                target = DTB_OFFSET
            else:
                target = TABLES_OFFSET + level * 0x1000
            off = table + ((DTB_VADDR >> shift) & 0x1FF) * 8
            buffer[off : off + 8] = struct.pack("<Q", target | 0x3)
            table = target
    return bytes(buffer)


def select(levels: Optional[int], l5_flag: Optional[bool]):
    context = contexts.Context()
    base = physical.BufferDataLayer(context, "test.base", "base", build_image(levels))
    context.add_layer(base)
    context.config[f"{CONFIG_PATH}.memory_layer"] = "base"
    context.config[f"{CONFIG_PATH}.page_map_offset"] = DTB_OFFSET
    return linux.LinuxIntelStacker.select_intel64_layer_class(
        context,
        CONFIG_PATH,
        LAYER_NAME,
        DTB_VADDR,
        l5_flag,
        intel.LinuxIntel32e,
        intel.LinuxIntel32e_LA57,
    )


class TestSelectIntel64LayerClass:
    @pytest.mark.parametrize("l5_flag", [None, False, True])
    def test_5level_tables_win_over_flag(self, l5_flag):
        # Missing (e.g. kernels 4.14-4.16) or wrong flags do not matter when
        # only one walk maps the top-level table to itself
        assert select(5, l5_flag) is intel.LinuxIntel32e_LA57

    @pytest.mark.parametrize("l5_flag", [None, False, True])
    def test_4level_tables_win_over_flag(self, l5_flag):
        assert select(4, l5_flag) is intel.LinuxIntel32e

    @pytest.mark.parametrize(
        "l5_flag, expected",
        [
            (None, intel.LinuxIntel32e),
            (False, intel.LinuxIntel32e),
            (True, intel.LinuxIntel32e_LA57),
        ],
    )
    def test_flag_decides_when_neither_walk_works(self, l5_flag, expected):
        assert select(None, l5_flag) is expected
