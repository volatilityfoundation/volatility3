# This file is Copyright 2026 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
"""Unit tests for the Linux automagic, focused on LA57 (5-level paging)
detection in the banner stacker.

These build synthetic page tables inside a BufferDataLayer and use a minimal
stand-in for the kernel symbol table, so no memory image or ISF is required.
"""

import struct
from types import SimpleNamespace
from typing import Dict, Optional

import pytest

from volatility3.framework import contexts
from volatility3.framework.automagic import linux
from volatility3.framework.layers import physical

KERNEL_TEXT_BASE = 0xFFFFFFFF80000000
INIT_TASK_PADDR = 0x12000
L5_ENABLED_PADDR = 0x13000
INIT_TASK_SYMBOL = KERNEL_TEXT_BASE + INIT_TASK_PADDR
L5_ENABLED_SYMBOL = KERNEL_TEXT_BASE + L5_ENABLED_PADDR

DTB_OFFSET = 0x1000
TABLES_OFFSET = 0x2000
BUFFER_SIZE = 0x20000

CONFIG_PATH = "test.intel"
LAYER_NAME = "intel_layer"


class FakeTable:
    """Minimal stand-in for LinuxKernelIntermedSymbols."""

    def __init__(self, symbols: Dict[str, int]) -> None:
        self._symbols = symbols

    @property
    def symbols(self):
        return list(self._symbols)

    def get_symbol(self, name: str):
        return SimpleNamespace(address=self._symbols[name])


def build_image(levels: int, l5_enabled: Optional[int] = None) -> bytes:
    """Builds a physical image whose DTB maps init_task's kernel text address
    using the given number of paging levels (4K pages, no KASLR)."""
    buffer = bytearray(BUFFER_SIZE)
    shifts = [48, 39, 30, 21, 12][5 - levels :]
    table = DTB_OFFSET
    for level, shift in enumerate(shifts):
        if level == len(shifts) - 1:
            target = INIT_TASK_PADDR
        else:
            target = TABLES_OFFSET + level * 0x1000
        off = table + ((INIT_TASK_SYMBOL >> shift) & 0x1FF) * 8
        buffer[off : off + 8] = struct.pack("<Q", target | 0x3)
        table = target
    if l5_enabled is not None:
        buffer[L5_ENABLED_PADDR : L5_ENABLED_PADDR + 4] = struct.pack("<I", l5_enabled)
    return bytes(buffer)


def l5_paging_enabled(levels: int, l5_enabled: Optional[int] = None) -> bool:
    context = contexts.Context()
    base = physical.BufferDataLayer(
        context, "test.base", "base", build_image(levels, l5_enabled)
    )
    context.add_layer(base)
    context.config[f"{CONFIG_PATH}.memory_layer"] = "base"
    context.config[f"{CONFIG_PATH}.page_map_offset"] = DTB_OFFSET

    symbols = {"init_task": INIT_TASK_SYMBOL}
    if l5_enabled is not None:
        symbols["__pgtable_l5_enabled"] = L5_ENABLED_SYMBOL
    return linux.LinuxIntelStacker._l5_paging_enabled(
        context, "base", FakeTable(symbols), 0, 0, CONFIG_PATH, LAYER_NAME
    )


class TestL5PagingEnabled:
    @pytest.mark.parametrize("levels", [4, 5])
    def test_symbol_is_authoritative(self, levels):
        # __pgtable_l5_enabled wins over the page table structure
        assert l5_paging_enabled(levels, l5_enabled=1) is True
        assert l5_paging_enabled(levels, l5_enabled=0) is False

    def test_init_task_probe_detects_la57(self):
        # No __pgtable_l5_enabled (e.g. kernels 4.14-4.16): only a 5-level
        # walk maps init_task to its physical address
        assert l5_paging_enabled(5) is True

    def test_init_task_probe_detects_4level(self):
        assert l5_paging_enabled(4) is False
