# This file is Copyright 2025 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
"""Unit tests for the pure logic of the windows.malware.impscan plugin.

These exercise the IAT-detection and vicinity-scan logic directly (no memory
image required) by disassembling hand-built instruction bytes with capstone.
"""

import pytest

from volatility3.framework import exceptions

capstone = pytest.importorskip("capstone")

from volatility3.plugins.windows.malware.impscan import ImpScan  # noqa: E402


def _disasm_one(code: bytes, address: int, mode):
    md = capstone.Cs(capstone.CS_ARCH_X86, mode)
    md.detail = True
    return next(md.disasm(code, address))


def test_iat_target_x86_call_absolute():
    # call dword ptr [0x401000]
    inst = _disasm_one(b"\xff\x15\x00\x10\x40\x00", 0x1000, capstone.CS_MODE_32)
    assert ImpScan._iat_target(inst, is_64bit=False) == 0x401000


def test_iat_target_x86_jmp_absolute():
    # jmp dword ptr [0x402000]
    inst = _disasm_one(b"\xff\x25\x00\x20\x40\x00", 0x1000, capstone.CS_MODE_32)
    assert ImpScan._iat_target(inst, is_64bit=False) == 0x402000


def test_iat_target_x64_call_rip_relative():
    # call qword ptr [rip + 0x989d] at 0x1000; target = 0x1000 + 6 + 0x989d
    inst = _disasm_one(b"\xff\x15\x9d\x98\x00\x00", 0x1000, capstone.CS_MODE_64)
    assert ImpScan._iat_target(inst, is_64bit=True) == 0x1000 + 6 + 0x989D


def test_iat_target_ignores_register_call():
    # call eax (register operand, not a memory/IAT reference)
    inst = _disasm_one(b"\xff\xd0", 0x1000, capstone.CS_MODE_32)
    assert ImpScan._iat_target(inst, is_64bit=False) is None


def test_iat_target_ignores_non_branch():
    inst = _disasm_one(b"\x90", 0x1000, capstone.CS_MODE_32)  # nop
    assert ImpScan._iat_target(inst, is_64bit=False) is None


def test_call_scan_resyncs_past_undecodable_bytes():
    # capstone stops at the first byte it cannot decode (0xffff is an invalid
    # FF /7 encoding). call_scan must skip it and still find the real
    # "call dword [0x1004]" that follows.
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    md.detail = True
    scanner = ImpScan.__new__(ImpScan)
    data = b"\xff\xff" + b"\xff\x15\x04\x10\x00\x00"
    results = list(scanner.call_scan(md.disasm, 0x1000, data, is_64bit=False))
    assert (0x1002, 0x1004) in results


def test_original_import_remaps_forwarded():
    scanner = ImpScan.__new__(ImpScan)
    assert scanner._original_import("ntdll.dll", "RtlAllocateHeap") == (
        "kernel32.dll",
        "HeapAlloc",
    )


def test_original_import_passes_through_normal():
    scanner = ImpScan.__new__(ImpScan)
    assert scanner._original_import("ws2_32.dll", "connect") == (
        "ws2_32.dll",
        "connect",
    )


class _FakeLayer:
    """Minimal layer returning little-endian pointers from a backing dict."""

    def __init__(self, pointers, ptr_size):
        self._pointers = pointers
        self._ptr_size = ptr_size

    def read(self, address, length):
        if address not in self._pointers:
            raise exceptions.InvalidAddressException("fake", address, "no mapping")
        return self._pointers[address].to_bytes(length, "little")


def test_read_pointer_reads_and_handles_missing():
    layer = _FakeLayer({0x2000: 0xDEADBEEF}, 4)
    assert ImpScan._read_pointer(layer, 0x2000, 4) == 0xDEADBEEF
    assert ImpScan._read_pointer(layer, 0x9999, 4) is None


def test_vicinity_scan_recovers_adjacent_imports():
    # Two IAT entries 4 bytes apart both point at known APIs; only the first
    # was found by the call scan, the second should be recovered by walking.
    ptr_size = 4
    base, data_len = 0x400000, 0x1000
    api_a, api_b = 0x77000000, 0x77000010
    apis = {api_a: ("a.dll", "A"), api_b: ("b.dll", "B")}
    pointers = {0x500000: api_a, 0x500004: api_b}
    calls_imported = {0x500000: api_a}

    scanner = ImpScan.__new__(ImpScan)
    layer = _FakeLayer(pointers, ptr_size)
    scanner._vicinity_scan(
        layer, calls_imported, apis, base, data_len, ptr_size, forward=True
    )
    assert calls_imported.get(0x500004) == api_b
