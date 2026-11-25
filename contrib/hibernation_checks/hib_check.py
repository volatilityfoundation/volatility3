#!/usr/bin/env python3
"""hib_check.py : sanity-check the compression-set layout of a Windows hiberfil.sys.

Standalone (no Volatility needed). Prints header counters and walks the chain of "compression
sets" of the boot section and of the kernel section, for two layouts:

  23h2 : size field = bits 8-29 (22 bits), algorithm = bits 30-31 (0/1 = LZ77, 2/3 = LZ77+Huffman),
         KernelPagesProcessed at 0x230
  24h2 : size field = bits 8-28, bit 30 = LZ77+Huffman (otherwise plain LZ77),
         KernelPagesProcessed at 0x250
  24h2-early : same set rules as 24h2, KernelPagesProcessed at 0x238 (builds such as 26100.1742,
         26100.6584 and 28000.1340)

A layout is considered correct for a file when the chain of sets reaches EXACTLY the number of
pages announced in the header, without any invalid set header on the way.

Reported for each section (24h2 layout):
  * the kind of every set (raw / plain LZ77 / LZ77+Huffman) split by bit 29 and bit 30;
  * how many sets have bit 29, bit 31 or one of the bits 25-28 set, the largest size seen, and how
    many sets are larger than 64 KiB (impossible for a set of at most 16 pages);
  * how many Huffman sets do not cover exactly 16 pages (the layer used to ask the decompressor
    for 65536 bytes whatever the set, which fails on such a set; it now asks for the size of the set);
  * how many compressed sets the 23h2 rules would classify differently (algorithm) or size
    differently (bit 29 counted in the size).

With --decompress (needs `pip install xpress-lz77`), every compressed set of the boot and of the
kernel section is decompressed with the algorithm selected by each layout and the output size is
checked, so that the two layouts can be compared on the boot section too.

By default only counters are printed (no path, no hash, no section offset, no exact file size),
so that the output can be shared. --show-offsets adds the identifying values for local debugging.

Usage:  python3 hib_check.py hiberfil.sys [--decompress] [--show-offsets]
"""

import argparse
import collections
import mmap
import struct
import sys

PAGE = 4096
MAX_SET_PAGES = 16
NPFL_OFF, FBRP_OFF, FKRP_OFF = (
    0x58,
    0x68,
    0x70,
)  # NumPagesForLoader, FirstBootRestorePage, FirstKernelRestorePage
KPP_OFF = {
    "23h2": 0x230,
    "24h2": 0x250,
    "24h2-early": 0x238,
}  # where each layout reads KernelPagesProcessed
LAYOUTS = (
    "23h2",
    "24h2",
    "24h2-early",
)  # the two 24h2 entries only differ by that offset (same set-header rules)
SCAN_RANGE = range(0x88, 0x290, 8)  # the PerfInfo part of the header


class SetInfo(
    collections.namedtuple("SetInfo", "off n size algo pages nxt word descs")
):
    """One compression set. descs = [(first_pfn, page_count), ...]"""

    @property
    def raw(self):
        return self.size == self.pages * PAGE

    @property
    def data_off(self):
        return self.off + 4 + self.n * 8


def parse_header(word, layout):
    """Return (number_of_descriptors, size_of_compressed_data, algorithm) for a set header word."""
    n = word & 0xFF
    if layout.startswith("24h2"):
        size = (word >> 8) & 0x1FFFFF
        algo = "huffman" if (word >> 30) & 1 else "lz77"
    else:
        size = (word >> 8) & 0x3FFFFF
        algo = "huffman" if ((word >> 30) & 3) >= 2 else "lz77"
    return n, size, algo


def read_set(m, off, layout):
    """Return a SetInfo, or None if the set header is invalid."""
    if off < 0 or off + 12 > len(m):
        return None
    word = struct.unpack_from("<I", m, off)[0]
    n, size, algo = parse_header(word, layout)
    if n == 0 or n > MAX_SET_PAGES or size == 0:
        return None
    if off + 4 + n * 8 > len(m):
        return None
    descs, pages = [], 0
    for i in range(n):
        d = struct.unpack_from("<Q", m, off + 4 + i * 8)[0]
        count = (d & 0xF) + 1
        descs.append((d >> 4, count))
        pages += count
    nxt = off + 4 + n * 8 + size
    if nxt > len(m):
        return None
    return SetInfo(off, n, size, algo, pages, nxt, word, descs)


def walk(m, start, wanted_pages, layout, keep=False):
    """Walk the chain of sets. Return (end_offset, pages, count, status, sets_or_None)."""
    off, pages, count = start, 0, 0
    sets = [] if keep else None
    status = "ok"
    while pages < wanted_pages:
        s = read_set(m, off, layout)
        if s is None:
            status = "INVALID SET HEADER"
            break
        if keep:
            sets.append(s)
        pages += s.pages
        off = s.nxt
        count += 1
    return off, pages, count, status, sets


def section_stats(sets):
    """Counters about the header bits of a section, computed with the 24h2 rules."""
    st = collections.Counter()
    max_size = 0
    kinds = collections.Counter()
    for s in sets:
        w = s.word
        kind = "raw" if s.raw else ("huffman" if s.algo == "huffman" else "plain-lz77")
        kinds[(kind, (w >> 29) & 1, (w >> 30) & 1)] += 1
        for bit in (25, 26, 27, 28, 29, 30, 31):
            if (w >> bit) & 1:
                st[f"bit{bit} set"] += 1
        max_size = max(max_size, s.size)
        if s.size > MAX_SET_PAGES * PAGE:
            st["sets larger than 64 KiB"] += 1
        if kind == "huffman" and s.pages != MAX_SET_PAGES:
            st["huffman sets with pages != 16"] += 1
        if not s.raw:
            _, size23, algo23 = parse_header(w, "23h2")
            if algo23 != s.algo:
                st["compressed sets classified differently by the 23h2 rules"] += 1
            if size23 != s.size:
                st["compressed sets sized differently by the 23h2 rules"] += 1
    return kinds, st, max_size


def decompress_counts(m, sets, lib):
    """Decompress every compressed set the way the layer does and check the output size.
    Return {algo: [ok, failed, failed_with_65536_but_ok_with_the_size_of_the_set]}."""
    res = {"lz77": [0, 0, 0], "huffman": [0, 0, 0]}
    for s in sets:
        if s.raw:
            continue
        data = bytes(m[s.data_off : s.data_off + s.size])
        want = s.pages * PAGE
        try:
            if s.algo == "huffman":
                out = lib.lz77_huffman_decompress_py(
                    data, 65536
                )  # what the layer did before the fix
            else:
                out = lib.lz77_plain_decompress_py(data)
            good = len(out) == want
        except BaseException:
            good = False
        if good:
            res[s.algo][0] += 1
        else:
            res[s.algo][1] += 1
            if s.algo == "huffman" and want != 65536:
                try:
                    good = len(lib.lz77_huffman_decompress_py(data, want)) == want
                except BaseException:
                    good = False
                res["huffman"][2] += good
    return res


def _print_stats(title, sets):
    kinds, st, max_size = section_stats(sets)
    print(f"  {title}: set kinds (kind, bit29, bit30):")
    for k, v in sorted(kinds.items()):
        print(f"     {k[0]:<11} bit29={k[1]} bit30={k[2]} : {v}")
    print(
        f"  {title}: largest set size {max_size} bytes "
        f"({max_size.bit_length()} bits), header bits set:"
    )
    for bit in (25, 26, 27, 28, 29, 30, 31):
        print(f"     bit {bit} : {st[f'bit{bit} set']} sets")
    for key in (
        "sets larger than 64 KiB",
        "huffman sets with pages != 16",
        "compressed sets classified differently by the 23h2 rules",
        "compressed sets sized differently by the 23h2 rules",
    ):
        print(f"  {title}: {key} : {st[key]}")


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Sanity-check the compression-set layout of a Windows hiberfil.sys"
    )
    ap.add_argument("hiberfil")
    ap.add_argument(
        "--decompress",
        action="store_true",
        help="decompress every compressed set (needs xpress-lz77)",
    )
    ap.add_argument(
        "--show-offsets",
        action="store_true",
        help="also print identifying values (exact size, section start pages, end offsets)",
    )
    args = ap.parse_args(argv)
    with open(args.hiberfil, "rb") as f:
        m = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)

    print(f"signature            : {bytes(m[:4])!r}")
    print(f"file size            : about {round(len(m) / 2**30)} GiB")
    npfl = struct.unpack_from("<Q", m, NPFL_OFF)[0]
    fbrp = struct.unpack_from("<Q", m, FBRP_OFF)[0]
    fkrp = struct.unpack_from("<Q", m, FKRP_OFF)[0]
    print(f"NumPagesForLoader    : {npfl}")
    if args.show_offsets:
        print(f"file size (bytes)    : {len(m)}")
        print(f"FirstBootRestorePage : {fbrp}")
        print(f"FirstKernelRestorePage: {fkrp}")

    lib = None
    if args.decompress:
        try:
            import xpress_lz77 as lib
        except ImportError:
            print("--decompress needs: pip install xpress-lz77")
    walked = {}
    for lay in LAYOUTS:
        print(f"\n=== layout {lay} (KernelPagesProcessed @ 0x{KPP_OFF[lay]:x}) ===")
        kpp = struct.unpack_from("<Q", m, KPP_OFF[lay])[0]
        print(f"KernelPagesProcessed : {kpp}")
        keep = True  # the sets of a matching chain are reused by the header-bit and decompression reports
        end, bp, bc, bs, bsets = walk(m, fbrp * PAGE, npfl, lay, keep=keep)
        verdict = "MATCH" if bp == npfl and bs == "ok" else "MISMATCH"
        print(f"boot section         : {bc} sets, {bp}/{npfl} pages, {bs}, {verdict}")
        walked[(lay, "boot")] = bsets if bp == npfl and bs == "ok" else None
        if kpp == 0:
            print(
                "kernel section       : KernelPagesProcessed is 0 -> kernel section would be skipped"
            )
            continue
        end, kp, kc, ks, ksets = walk(m, fkrp * PAGE, kpp, lay, keep=keep)
        verdict = "MATCH" if kp == kpp and ks == "ok" else "MISMATCH"
        ends = f", ends at byte {end}" if args.show_offsets else ""
        print(
            f"kernel section       : {kc} sets, {kp}/{kpp} pages, {ks}, {verdict}{ends}"
        )
        walked[(lay, "kernel")] = ksets if kp == kpp and ks == "ok" else None

    # header bits of each section, taken from the first layout whose chain matches it
    # (24h2 rules first; a kernel section that only walks with the 23h2 rules is reported as well)
    print("\n=== header bits, 24h2 rules ===")
    for sec in ("boot", "kernel"):
        for lay in ("24h2", "24h2-early", "23h2"):
            if walked.get((lay, sec)):
                print(f"  ({sec} section: sets of the {lay} layout)")
                _print_stats(sec, walked[(lay, sec)])
                break
        else:
            print(f"  ({sec} section: no layout matches, nothing to report)")

    # independent of any offset: walk the kernel chain until it ends by itself, then see which header
    # qwords hold the same page count (and the byte length of the section)
    for rules in ("23h2", "24h2"):
        end, kp, kc, ks, _ = walk(m, fkrp * PAGE, 1 << 60, rules)
        found = [o for o in SCAN_RANGE if struct.unpack_from("<Q", m, o)[0] == kp]
        blen = end - fkrp * PAGE
        foundb = [o for o in SCAN_RANGE if struct.unpack_from("<Q", m, o)[0] == blen]
        print(f"\n=== kernel chain walked to its natural end, {rules} set rules ===")
        found_txt = ", ".join(f"0x{o:x}" for o in found) or "none"
        foundb_txt = ", ".join(f"0x{o:x}" for o in foundb) or "none"
        print(
            f"{kc} sets, {kp} pages | header qwords equal to that page count: "
            f"{found_txt} | equal to its length in bytes: {foundb_txt}"
        )

    if lib is not None:
        print(
            "\n=== decompression (algorithm selected by each layout; output size checked) ==="
        )
        for lay in LAYOUTS:
            for sec in ("boot", "kernel"):
                sets = walked.get((lay, sec))
                if not sets:
                    print(
                        f"{lay} layout, {sec} section: not walked (section skipped or chain does not match)"
                    )
                    continue
                r = decompress_counts(m, sets, lib)
                comp = sum(1 for s in sets if not s.raw)
                lz_ok, lz_bad = r["lz77"][:2]
                hf_ok, hf_bad, hf_rescued = r["huffman"]
                print(
                    f"{lay} layout, {sec} section: {comp} compressed sets | "
                    f"plain LZ77 ok={lz_ok} failed={lz_bad} | "
                    f"Huffman ok={hf_ok} failed={hf_bad} "
                    f"(failed with the fixed 65536 size, ok with the size of the set: {hf_rescued})"
                )
    return 0


if __name__ == "__main__":
    sys.exit(main())
