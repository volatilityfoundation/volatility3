#!/usr/bin/env python3
"""count_nonzero_pages.py : count the 4 KiB pages that contain at least one non-zero byte in a raw
memory image (e.g. the output of windows.hibernation.Dump). Prints only counters.
Usage: python3 count_nonzero_pages.py memory_layer.raw   (needs numpy)"""

import sys
import numpy as np

PAGE = 4096
CHUNK = 256 * 1024 * 1024
total = nonzero = 0
with open(sys.argv[1], "rb") as f:
    while True:
        b = f.read(CHUNK)
        if not b:
            break
        a = np.frombuffer(b[: len(b) // PAGE * PAGE], dtype=np.uint64).reshape(
            -1, PAGE // 8
        )
        total += a.shape[0]
        nonzero += int(a.any(axis=1).sum())
print(
    f"pages total={total} non-zero={nonzero} ({nonzero * PAGE / 2**20:.0f} MiB) zero={total - nonzero}"
)
