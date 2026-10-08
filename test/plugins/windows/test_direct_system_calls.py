import struct
import sys
import unittest

sys.path.insert(0, "../../volatility3")
from volatility3.framework import exceptions
from volatility3.plugins.windows.malware import direct_system_calls
from volatility3.plugins.windows.malware import indirect_system_calls

# A minimal x86-64 direct system call stub, matching the shape reported in
# issue #1930:
#
#   4c 8b d1              mov  r10, rcx
#   8b 05 <disp32>        mov  eax, dword ptr [rip + disp32]
#   0f 05                 syscall
#   c3                    ret
#
# The stub is 12 bytes long and the `syscall` instruction sits 9 bytes in.
STUB_LENGTH = 12
SYSCALL_OFFSET = 9

MOV_R10_RCX = b"\x4c\x8b\xd1"
MOV_EAX_IMM = b"\xb8\x3a\x00\x00\x00"
XOR_RBX_RBX = b"\x48\x31\xdb"
PUSH_POP_RBX = b"\x53\x5b"
SYSCALL = b"\x0f\x05"
RET = b"\xc3"
NOP = b"\x90"

# The scan rule tolerates spacing between the `syscall` and the `ret` so that
# anti-analysis variants such as TartarusGate are still caught. Each of these
# must therefore resolve to the start of its own stub.
OBFUSCATED_STUBS = {
    "classic": MOV_R10_RCX + MOV_EAX_IMM + SYSCALL + RET,
    "eax written before r10": MOV_EAX_IMM + MOV_R10_RCX + SYSCALL + RET,
    "nop spacing throughout": (
        MOV_R10_RCX + NOP * 3 + MOV_EAX_IMM + NOP * 3 + SYSCALL + NOP * 2 + RET
    ),
    "junk before the syscall": MOV_R10_RCX + MOV_EAX_IMM + XOR_RBX_RBX + SYSCALL + RET,
    "push and pop padding": MOV_R10_RCX + MOV_EAX_IMM + PUSH_POP_RBX + SYSCALL + RET,
    "twenty bytes of spacing": MOV_R10_RCX + MOV_EAX_IMM + NOP * 20 + SYSCALL + RET,
}


def make_stub(filler: int) -> bytes:
    """Builds a single syscall stub, using `filler` for the rip displacement.

    The displacement bytes differ between stubs so that a misattributed block
    can be told apart from the correct one in assertion failures.
    """
    return b"\x4c\x8b\xd1" + b"\x8b\x05" + bytes([filler]) * 4 + b"\x0f\x05" + b"\xc3"


class FakeLayer:
    """Stands in for a process translation layer over a fixed buffer.

    `_is_valid_syscall` only ever reads from the layer, so a buffer backed by
    a known base address is all that is required to exercise it.
    """

    def __init__(self, base: int, data: bytes) -> None:
        self._base = base
        self._data = data

    def read(self, offset: int, length: int, pad: bool = False) -> bytes:
        start = offset - self._base
        if start < 0 or start + length > len(self._data):
            raise exceptions.InvalidAddressException(
                "FakeLayer", offset, "read outside of the backing buffer"
            )
        return self._data[start : start + length]


class TestDirectSystemCallBlocks(unittest.TestCase):
    """Tests the mapping of a `syscall` hit back onto its enclosing block."""

    # Mirrors the finder built in DirectSystemCalls.__init__
    finder = direct_system_calls.syscall_finder_type(
        None,
        True,
        "/\\x0f\\x05[^\\xc3]{,24}\\xc3/",
        ["jmp", "call", "leave", "int3"],
        ["ret"],
    )

    # The look-behind window `_is_valid_syscall` reads before each hit
    lookbehind = 32

    def _build(self, region: bytes, region_base: int) -> FakeLayer:
        """Wraps `region` in padding so look-behind and look-ahead succeed."""
        pad = b"\x90" * self.lookbehind * 2
        return FakeLayer(region_base - len(pad), pad + region + pad)

    def test_packed_stubs_each_report_their_own_block(self):
        """Each hit must resolve to the stub that contains it.

        Malware that inlines a table of syscall stubs packs them back to
        back, so the 32 byte look-behind of one hit covers the whole of the
        preceding stub. That preceding stub is itself a well formed block,
        and must not be reported in place of the real one.
        """
        base = 0x1000
        count = 4
        region = b"".join(make_stub(0xA0 + index) for index in range(count))
        layer = self._build(region, base)

        for index in range(count):
            expected = base + index * STUB_LENGTH
            hit = expected + SYSCALL_OFFSET

            result = direct_system_calls.DirectSystemCalls._is_valid_syscall(
                self.finder, layer, "intel64", [], hit
            )

            self.assertIsNotNone(result, f"no block found for hit {hit:#x}")
            self.assertEqual(
                result[0],
                expected,
                f"hit {hit:#x} was attributed to block {result[0]:#x} "
                f"instead of {expected:#x}",
            )

    def test_block_starts_at_the_stub_not_at_preceding_padding(self):
        """A block must not be grown backwards through benign padding.

        Disassembling from part way into a run of single byte nops still
        reaches the stub that follows it, so many offsets in the look-behind
        window decode into a valid looking block. The reported block should
        be the stub itself rather than the earliest of those offsets.
        """
        base = 0x2000
        layer = self._build(make_stub(0xC3), base)
        hit = base + SYSCALL_OFFSET

        result = direct_system_calls.DirectSystemCalls._is_valid_syscall(
            self.finder, layer, "intel64", [], hit
        )

        self.assertIsNotNone(result, "no block found for a lone padded stub")
        self.assertEqual(result[0], base)
        self.assertNotIn(
            "nop",
            result[1],
            "the reported disassembly reaches back into the padding",
        )

    def test_obfuscated_stubs_report_their_own_start(self):
        """Spaced and reordered stubs must still resolve to the stub itself.

        The look-behind window covers whatever precedes the stub, so each of
        these forms previously reported a block starting in that padding.
        """
        base = 0x5000

        for name, stub in OBFUSCATED_STUBS.items():
            with self.subTest(variant=name):
                layer = self._build(stub, base)
                hit = base + stub.index(SYSCALL)

                result = direct_system_calls.DirectSystemCalls._is_valid_syscall(
                    self.finder, layer, "intel64", [], hit
                )

                self.assertIsNotNone(result, f"{name} was not detected at all")
                self.assertEqual(result[0], base)


class TestIndirectSystemCallBlocks(unittest.TestCase):
    """Guards the indirect technique, which shares the block matching code.

    Indirect blocks terminate on a `jmp` rather than containing a `syscall`
    themselves, so the instruction that the scan rule matches is the `jmp`.
    """

    lookbehind = 32

    def test_indirect_block_is_still_matched(self):
        base = 0x3000
        # jmp [rip + disp32] dereferences this slot, which points at a
        # `syscall` instruction inside a range owned by ntdll
        pointer_slot = 0x3080
        syscall_site = 0x3100

        jmp_site = base + 9
        displacement = pointer_slot - jmp_site - 6

        stub = (
            b"\x4c\x8b\xd1"  # mov  r10, rcx
            + b"\x8b\x05"
            + b"\x11" * 4  # mov  eax, dword ptr [rip + 0x11111111]
            + b"\xff\x25"
            + struct.pack("<I", displacement)  # jmp  qword ptr [rip + disp32]
        )

        buffer_base = 0x2F00
        data = bytearray(b"\x90" * 0x400)
        data[base - buffer_base : base - buffer_base + len(stub)] = stub
        data[pointer_slot - buffer_base : pointer_slot - buffer_base + 8] = struct.pack(
            "<Q", syscall_site
        )
        data[syscall_site - buffer_base : syscall_site - buffer_base + 2] = b"\x0f\x05"

        layer = FakeLayer(buffer_base, bytes(data))
        vads = [(syscall_site, 0x10, "\\Windows\\System32\\ntdll.dll")]

        plugin = indirect_system_calls.IndirectSystemCalls
        finder = direct_system_calls.syscall_finder_type(
            plugin._indirect_syscall_block_target,
            False,
            "/\\xff\\x25[^\\xc3]{,24}\\xc3/",
            ["call", "leave", "int3", "ret"],
            ["jmp"],
        )

        result = plugin._is_valid_syscall(finder, layer, "intel64", vads, jmp_site)

        self.assertIsNotNone(result, "the indirect syscall block was not matched")
        self.assertEqual(result[0], base)


if __name__ == "__main__":
    unittest.main()
