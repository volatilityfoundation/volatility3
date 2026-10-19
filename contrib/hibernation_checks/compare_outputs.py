#!/usr/bin/env python3
"""compare_outputs.py : compare two raw images produced by windows.hibernation.Dump from the same
hiberfil.sys (for example --version 0 with the original code and --version 4 with the patched
code), section by section.

The hibernation file tells which physical pages belong to the boot section and to the kernel
section (the page descriptors of every compression set, parsed with the 24h2 layout). For each of
these pages the script counts how the two images relate:

    identical, non-zero       the two images have the same non-zero content
    identical, zero           both are all-zero
    differ, both non-zero     both have data but it differs   (a decoding difference)
    only B has data           zero in A, data in B            (pages recovered by B)
    only A has data           data in A, zero in B            (pages lost by B: should be 0)

Expected for the patch: the boot section is unchanged (everything "identical"), and the kernel
section goes from "zero" in A to "data" in B.

The raw image is a physical-memory image: page N is at byte offset N * 4096.
Only counters are printed (no path, no hash, no image size). --outside also scans the whole images for pages that
differ OUTSIDE the two sections (slow on a large image).

Usage: python3 compare_outputs.py hiberfil.sys imageA.raw imageB.raw [--outside]
"""

import argparse
import mmap
import struct
import sys

import hib_check as hc

PAGE = hc.PAGE
ZERO = bytes(PAGE)
CATEGORIES = (
    "identical, non-zero",
    "identical, zero",
    "differ, both non-zero",
    "only B has data",
    "only A has data",
)


def section_pages(m, layout="24h2"):
    """Return {'boot': [(pfn, count), ...], 'kernel': [...]} from the hibernation file, or raise ValueError."""
    npfl = struct.unpack_from("<Q", m, hc.NPFL_OFF)[0]
    fbrp = struct.unpack_from("<Q", m, hc.FBRP_OFF)[0]
    fkrp = struct.unpack_from("<Q", m, hc.FKRP_OFF)[0]
    kpp = struct.unpack_from("<Q", m, hc.KPP_OFF[layout])[0]
    out = {}
    for name, start, wanted in (("boot", fbrp, npfl), ("kernel", fkrp, kpp)):
        _, pages, _, status, sets = hc.walk(m, start * PAGE, wanted, layout, keep=True)
        if status != "ok" or pages != wanted:
            raise ValueError(
                f"the {name} section does not walk cleanly with the {layout} layout "
                f"({status}, {pages}/{wanted} pages)"
            )
        out[name] = [d for s in sets for d in s.descs]
    return out


def read_page(mm, pfn):
    off = pfn * PAGE
    chunk = bytes(mm[off : off + PAGE]) if off < len(mm) else b""
    return chunk if len(chunk) == PAGE else chunk + bytes(PAGE - len(chunk))


def compare_ranges(a, b, ranges):
    """Count, for every page of the (pfn, count) ranges, how image A and image B relate."""
    counts = dict.fromkeys(CATEGORIES, 0)
    for pfn, count in ranges:
        for p in range(pfn, pfn + count):
            pa, pb = read_page(a, p), read_page(b, p)
            if pa == pb:
                counts["identical, zero" if pa == ZERO else "identical, non-zero"] += 1
            elif pa == ZERO:
                counts["only B has data"] += 1
            elif pb == ZERO:
                counts["only A has data"] += 1
            else:
                counts["differ, both non-zero"] += 1
    return counts


def outside_differences(a, b, ranges_all, chunk_pages=4096):
    """Count the pages that differ between the two images and are not in any section range."""
    total = max(len(a), len(b)) // PAGE
    in_section = bytearray(total + 1)
    for pfn, count in ranges_all:
        for p in range(pfn, min(pfn + count, total + 1)):
            in_section[p] = 1
    differing = 0
    for first in range(0, total, chunk_pages):
        last = min(first + chunk_pages, total)
        ca = bytes(a[first * PAGE : last * PAGE])
        cb = bytes(b[first * PAGE : last * PAGE])
        if ca == cb:
            continue
        for p in range(first, last):
            o = (p - first) * PAGE
            if ca[o : o + PAGE] != cb[o : o + PAGE] and not in_section[p]:
                differing += 1
    return differing


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Compare two windows.hibernation.Dump outputs section by section"
    )
    ap.add_argument("hiberfil")
    ap.add_argument("image_a")
    ap.add_argument("image_b")
    ap.add_argument(
        "--outside",
        action="store_true",
        help="also count differing pages outside both sections",
    )
    args = ap.parse_args(argv)
    with open(args.hiberfil, "rb") as f:
        hib = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
    try:
        sections = section_pages(hib)
    except ValueError as exc:
        print(f"cannot compare: {exc}")
        return 1
    with open(args.image_a, "rb") as fa, open(args.image_b, "rb") as fb:
        a = mmap.mmap(fa.fileno(), 0, access=mmap.ACCESS_READ)
        b = mmap.mmap(fb.fileno(), 0, access=mmap.ACCESS_READ)
        for name in ("boot", "kernel"):
            counts = compare_ranges(a, b, sections[name])
            total = sum(c for _, c in sections[name])
            print(f"\n{name} section ({total} pages):")
            for cat in CATEGORIES:
                print(f"   {cat:<24} : {counts[cat]}")
        if args.outside:
            allr = sections["boot"] + sections["kernel"]
            diff = outside_differences(a, b, allr)
            print(f"\npages that differ outside both sections : {diff}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
