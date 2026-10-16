#!/usr/bin/env python3
"""Synthetic tests for hib_check.py / compare_outputs.py. No sample data: every hibernation file
used here is generated in memory from a few hand-made compression sets.

They check that the tools parse the 24H2 set header the way the patch does, and that they would
notice the problems described in the PR (bit 29 taken as part of the size, bit 30 as Huffman).
They do NOT exercise Volatility itself.

Run:  python3 -m unittest -v test_hib_layout        (from the tests/ directory)
      (the decompression tests are skipped unless `pip install xpress-lz77` is available)
"""

import contextlib
import io
import os
import pathlib
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import compare_outputs as co  # noqa: E402
import hib_check as hc  # noqa: E402

try:
    import xpress_lz77
except ImportError:  # pragma: no cover
    xpress_lz77 = None

PAGE = hc.PAGE


# ----------------------------------------------------------------------------- builders
def plain_lz77_literals(data):
    """Valid plain LZ77 stream made of literals only (a flags word of zeros before every 32 bytes)."""
    out = bytearray()
    for i in range(0, len(data), 32):
        chunk = data[i : i + 32]
        flags = 0 if len(chunk) == 32 else (0xFFFFFFFF >> len(chunk))
        out += struct.pack("<I", flags) + chunk
    return bytes(out)


def huffman_single_byte(byte, count):
    """Valid LZ77+Huffman stream decoding to `count` copies of `byte` (symbols {byte, 256}, 1-bit codes)."""
    lengths = [0] * 512
    lengths[byte] = 1
    lengths[256] = 1
    table = bytearray(256)
    for i in range(256):
        table[i] = lengths[2 * i] | (lengths[2 * i + 1] << 4)
    first, second = sorted((byte, 256))
    code = {first: 0, second: 1}
    bits = [code[byte]] * count + [code[256]]
    while len(bits) % 16:
        bits.append(0)
    words = bytearray()
    for i in range(0, len(bits), 16):
        w = 0
        for b in bits[i : i + 16]:
            w = (w << 1) | b
        words += struct.pack("<H", w)
    return bytes(table) + bytes(words) + b"\x00\x00\x00\x00"


def make_set(kind, first_pfn, pages, extra_bits=0, fill=0x41):
    """Return (set_bytes, decoded_pages_bytes, [(pfn, count), ...]) for a synthetic compression set."""
    if kind == "huffman":
        decoded = bytes([fill]) * (pages * PAGE)
        data = huffman_single_byte(fill, pages * PAGE)
        flags = 1 << 30
    elif kind == "plain":
        decoded = bytes(((i * 7 + fill) & 0xFF) for i in range(pages * PAGE))
        data = plain_lz77_literals(decoded)
        flags = 0
    else:
        decoded = bytes(((i * 13 + fill) & 0xFF) for i in range(pages * PAGE))
        data = decoded
        flags = 0
    # descriptors of at most 8 pages, so that a 16-page set has two of them (like the real example)
    descs, left, pfn = [], pages, first_pfn
    while left:
        c = min(8, left)
        descs.append((pfn, c))
        pfn += c
        left -= c
    word = len(descs) | (len(data) << 8) | flags | extra_bits
    blob = struct.pack("<I", word & 0xFFFFFFFF)
    for p, c in descs:
        blob += struct.pack("<Q", (p << 4) | (c - 1))
    return blob + data, decoded, descs


class Synth:
    """A tiny hiberfil.sys: header, a boot section and a kernel section."""

    BOOT_PAGE, KERNEL_PAGE = 4, 200

    def __init__(self, boot_specs, kernel_specs, layout="24h2"):
        self.decoded = {}  # pfn -> page bytes
        self.ranges = {"boot": [], "kernel": []}
        boot_blob, boot_pages = self._section("boot", boot_specs)
        kernel_blob, kernel_pages = self._section("kernel", kernel_specs)
        size = (self.KERNEL_PAGE + 1) * PAGE + len(kernel_blob) + PAGE
        img = bytearray(size)
        img[0:4] = b"HIBR"
        struct.pack_into("<Q", img, hc.NPFL_OFF, boot_pages)
        struct.pack_into("<Q", img, hc.FBRP_OFF, self.BOOT_PAGE)
        struct.pack_into("<Q", img, hc.FKRP_OFF, self.KERNEL_PAGE)
        struct.pack_into("<Q", img, hc.KPP_OFF[layout], kernel_pages)
        assert len(boot_blob) < (self.KERNEL_PAGE - self.BOOT_PAGE) * PAGE
        img[self.BOOT_PAGE * PAGE : self.BOOT_PAGE * PAGE + len(boot_blob)] = boot_blob
        img[self.KERNEL_PAGE * PAGE : self.KERNEL_PAGE * PAGE + len(kernel_blob)] = (
            kernel_blob
        )
        self.data = bytes(img)
        self.boot_pages, self.kernel_pages = boot_pages, kernel_pages

    def _section(self, name, specs):
        blob, pages = b"", 0
        for kind, pfn, npages, extra in specs:
            s, decoded, descs = make_set(kind, pfn, npages, extra)
            blob += s
            pages += npages
            self.ranges[name] += descs
            for i in range(npages):
                self.decoded[pfn + i] = decoded[i * PAGE : (i + 1) * PAGE]
        return blob, pages

    def write(self, directory, name="hiberfil.sys"):
        path = os.path.join(directory, name)
        with open(path, "wb") as f:
            f.write(self.data)
        return path


BIT29, BIT31 = 1 << 29, 1 << 31

# Boot: raw + plain (no bit 29) + a Huffman set with bit 29.  Kernel: every kind, bit 29 on some,
# and one plain set with bit 31 set (unknown bit, must be counted).
BOOT = [("raw", 100, 2, 0), ("plain", 110, 3, 0), ("huffman", 120, 16, BIT29)]
KERNEL = [
    ("plain", 300, 4, 0),
    ("huffman", 320, 16, BIT29),
    ("huffman", 340, 16, 0),
    ("raw", 360, 2, BIT29),
    ("plain", 370, 2, BIT31),
    ("raw", 380, 3, 0),
]


def run_check(path, *flags):
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        hc.main([path, *flags])
    return buf.getvalue()


# ----------------------------------------------------------------------------- tests
class HeaderParsing(unittest.TestCase):
    def test_example_from_the_pr(self):
        w = 0x6010C302
        self.assertEqual(
            hc.parse_header(w, "23h2"), (2, 2101443, "lz77")
        )  # old rules: impossible size, bit 30 = plain
        self.assertEqual(
            hc.parse_header(w, "24h2"), (2, 4291, "huffman")
        )  # 24h2: bit 29 is not in the size, bit 30 = Huffman

    def test_only_bit29_differs_in_the_size_mask(self):
        self.assertEqual(0x3FFFFF ^ 0x1FFFFF, 1 << 21)  # word bit 29 = size bit 21
        self.assertLessEqual(
            (16 * PAGE).bit_length(), 17
        )  # a set of 16 pages never needs more than 17 bits

    def test_bit31_is_ignored_by_24h2(self):
        n, size, algo = hc.parse_header(BIT31 | (100 << 8) | 1, "24h2")
        self.assertEqual((n, size, algo), (1, 100, "lz77"))


class SyntheticFile(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.synth = Synth(BOOT, KERNEL)
        cls.path = cls.synth.write(cls.tmp.name)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_24h2_chains_match(self):
        out = run_check(self.path)
        self.assertIn(
            f"boot section         : 3 sets, {self.synth.boot_pages}/{self.synth.boot_pages} pages, ok, MATCH",
            out,
        )
        self.assertIn(
            f"kernel section       : 6 sets, {self.synth.kernel_pages}/{self.synth.kernel_pages} pages, ok, MATCH",
            out,
        )

    def test_23h2_layout_skips_the_kernel_section(self):
        out = run_check(self.path)
        self.assertIn("layout 23h2", out)
        self.assertIn(
            "KernelPagesProcessed is 0 -> kernel section would be skipped", out
        )

    def test_23h2_rules_break_on_bit29_huffman(self):
        # walking the kernel section with the 23h2 rules must fail on the Huffman set that has bit 29
        m = self.synth.data
        _, pages, _, status, _ = hc.walk(
            m, Synth.KERNEL_PAGE * PAGE, self.synth.kernel_pages, "23h2"
        )
        self.assertEqual(status, "INVALID SET HEADER")
        self.assertLess(pages, self.synth.kernel_pages)

    def test_stats_and_bit_counters(self):
        out = run_check(self.path)
        self.assertIn("kernel: set kinds", out)
        # kernel: 1 raw with bit 29, 1 raw without, 2 huffman (one with bit 29), 2 plain
        kernel_part = out.split("kernel: set kinds")[1].split("kernel: largest")[0]
        self.assertRegex(kernel_part, r"raw\s+bit29=0 bit30=0 : 1")
        self.assertRegex(kernel_part, r"raw\s+bit29=1 bit30=0 : 1")
        self.assertRegex(out, r"kernel: largest set size \d+ bytes")
        self.assertRegex(out, r"bit 31 : 1 sets")
        self.assertRegex(out, r"bit 25 : 0 sets")
        self.assertIn("kernel: huffman sets with pages != 16 : 0", out)
        self.assertIn("kernel: sets larger than 64 KiB : 0", out)
        # the 23h2 rules would read bit 29 as part of the size (1 compressed set has it) and would classify
        # 3 compressed sets differently: the 2 Huffman sets (bit 30 only = plain LZ77 there) and the plain set
        # that has bit 31 set (Huffman there)
        self.assertRegex(
            out, r"kernel: compressed sets sized differently by the 23h2 rules : 1"
        )
        self.assertRegex(
            out, r"kernel: compressed sets classified differently by the 23h2 rules : 3"
        )

    def test_default_output_hides_identifying_values(self):
        out = run_check(self.path)
        size = str(len(self.synth.data))
        for hidden in (
            size,
            "FirstBootRestorePage",
            "FirstKernelRestorePage",
            "ends at byte",
        ):
            self.assertNotIn(hidden, out)
        self.assertRegex(
            out, r"file size\s+: about \d+ GiB"
        )  # rounded, never the exact size
        shown = run_check(self.path, "--show-offsets")
        for visible in (
            size,
            f"FirstBootRestorePage : {Synth.BOOT_PAGE}",
            "ends at byte",
        ):
            self.assertIn(visible, shown)

    @unittest.skipIf(xpress_lz77 is None, "xpress-lz77 not installed")
    def test_decompression_24h2_and_23h2(self):
        out = run_check(self.path, "--decompress")
        # 24h2 rules: boot has 1 plain + 1 huffman, kernel 2 plain + 2 huffman; all decode
        self.assertIn(
            "24h2 layout, boot section: 2 compressed sets | plain LZ77 ok=1 failed=0 | Huffman ok=1 failed=0",
            out,
        )
        self.assertIn(
            "24h2 layout, kernel section: 4 compressed sets | plain LZ77 ok=2 failed=0 | Huffman ok=2 failed=0",
            out,
        )
        # 23h2 rules on the boot section: the Huffman set (bit 30 only) is read as plain LZ77 and cannot decode
        self.assertNotIn(
            "23h2 layout, boot section: 2 compressed sets | plain LZ77 ok=1 failed=0 | Huffman ok=1 failed=0",
            out,
        )

    @unittest.skipIf(xpress_lz77 is None, "xpress-lz77 not installed")
    def test_decoded_content_matches(self):
        m = self.synth.data
        _, _, _, _, sets = hc.walk(
            m, Synth.KERNEL_PAGE * PAGE, self.synth.kernel_pages, "24h2", keep=True
        )
        for s in sets:
            data = m[s.data_off : s.data_off + s.size]
            if s.raw:
                out = data
            elif s.algo == "huffman":
                out = bytes(xpress_lz77.lz77_huffman_decompress_py(bytes(data), 65536))
            else:
                out = bytes(xpress_lz77.lz77_plain_decompress_py(bytes(data)))
            expected = b"".join(
                self.synth.decoded[p + i][:] for p, c in s.descs for i in range(c)
            )
            self.assertEqual(out, expected)

    def test_raw_set_with_bit30_is_raw_not_huffman(self):
        synth = Synth(
            BOOT, [("raw", 300, 2, 1 << 30), ("raw", 310, 2, (1 << 30) | BIT29)]
        )
        out = run_check(synth.write(self.tmp.name, "raw_bit30.sys"))
        kernel_part = out.split("kernel: set kinds")[1].split("kernel: largest")[0]
        self.assertRegex(kernel_part, r"raw\s+bit29=0 bit30=1 : 1")
        self.assertRegex(kernel_part, r"raw\s+bit29=1 bit30=1 : 1")
        self.assertNotIn("huffman", kernel_part)

    def test_huffman_set_with_fewer_pages_is_reported(self):
        synth = Synth(
            BOOT, [("huffman", 300, 4, 0)]
        )  # 4 pages: not what the layer's fixed 65536 assumes
        out = run_check(synth.write(self.tmp.name, "small_huffman.sys"))
        self.assertIn("kernel: huffman sets with pages != 16 : 1", out)


class CompareOutputs(unittest.TestCase):
    def _images(self, directory, synth, with_kernel_in_a):
        total = 500
        a, b = bytearray(total * PAGE), bytearray(total * PAGE)
        for pfn, page in synth.decoded.items():
            in_kernel = any(p <= pfn < p + c for p, c in synth.ranges["kernel"])
            b[pfn * PAGE : (pfn + 1) * PAGE] = page
            if not in_kernel or with_kernel_in_a:
                a[pfn * PAGE : (pfn + 1) * PAGE] = page
        pa, pb = os.path.join(directory, "a.raw"), os.path.join(directory, "b.raw")
        pathlib.Path(pa).write_bytes(a)
        pathlib.Path(pb).write_bytes(b)
        return pa, pb

    def _run(self, *argv):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = co.main(list(argv))
        return rc, buf.getvalue()

    def test_boot_unchanged_kernel_recovered(self):
        with tempfile.TemporaryDirectory() as d:
            synth = Synth(BOOT, KERNEL)
            hib = synth.write(d)
            pa, pb = self._images(d, synth, with_kernel_in_a=False)
            rc, out = self._run(hib, pa, pb)
            self.assertEqual(rc, 0)
            boot, kernel = out.split("kernel section")
            self.assertRegex(boot, rf"identical, non-zero\s+: {synth.boot_pages}\n")
            self.assertRegex(boot, r"differ, both non-zero\s+: 0\n")
            self.assertRegex(kernel, rf"only B has data\s+: {synth.kernel_pages}\n")
            self.assertRegex(kernel, r"only A has data\s+: 0\n")

    def test_detects_a_changed_boot_page(self):
        with tempfile.TemporaryDirectory() as d:
            synth = Synth(BOOT, KERNEL)
            hib = synth.write(d)
            pa, pb = self._images(d, synth, with_kernel_in_a=True)
            b = bytearray(pathlib.Path(pb).read_bytes())
            b[100 * PAGE + 5] ^= 0xFF  # corrupt one boot page in B
            pathlib.Path(pb).write_bytes(b)
            rc, out = self._run(hib, pa, pb)
            self.assertRegex(
                out.split("kernel section")[0], r"differ, both non-zero\s+: 1\n"
            )

    def test_outside_scan(self):
        with tempfile.TemporaryDirectory() as d:
            synth = Synth(BOOT, KERNEL)
            hib = synth.write(d)
            pa, pb = self._images(d, synth, with_kernel_in_a=True)
            b = bytearray(pathlib.Path(pb).read_bytes())
            b[450 * PAGE + 1] = 1  # a page in neither section
            pathlib.Path(pb).write_bytes(b)
            rc, out = self._run(hib, pa, pb, "--outside")
            self.assertIn("pages that differ outside both sections : 1", out)

    def test_refuses_a_file_that_does_not_walk(self):
        with tempfile.TemporaryDirectory() as d:
            hib = os.path.join(d, "bad.sys")
            img = bytearray(b"HIBR" + bytes(PAGE * 8))
            struct.pack_into(
                "<Q", img, hc.NPFL_OFF, 5
            )  # 5 boot pages announced, but zeros where the first set should be
            pathlib.Path(hib).write_bytes(img)
            rc, out = self._run(hib, hib, hib)
            self.assertEqual(rc, 1)
            self.assertIn("cannot compare", out)


if __name__ == "__main__":
    unittest.main()
