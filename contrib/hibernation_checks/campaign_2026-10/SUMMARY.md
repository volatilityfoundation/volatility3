## Files and counter offset

| build | kernel | round | SystemTime of the file (UTC, guest clock) | KernelPagesProcessed found at | boot sets/pages | kernel sets/pages | Huffman sets with < 16 pages | decompression of the kernel section (hib_check.py) |
|---|---|---|---|---|---|---|---|---|
| 21H2 | 22000.318 | r0 | 2026-10-13 15:41:05+00:00 | 0x230 | 1571/25134 | 18447/295146 | 1 | 18369 sets: LZ77 22 ok / 0 failed, Huffman 18346 ok / 1 failed; 1 Huffman set(s) fail with the fixed 65536 and decode with the size of the set |
| 21H2 | 22000.318 | r1 | 2026-10-14 02:17:00+00:00 | 0x230 | 1569/25095 | 18445/295105 | 1 | 18347 sets: LZ77 21 ok / 0 failed, Huffman 18325 ok / 1 failed; 1 Huffman set(s) fail with the fixed 65536 and decode with the size of the set |
| 21H2 | 22000.318 | r2 | 2026-10-14 04:24:40+00:00 | 0x230 | 1571/25124 | 18489/295820 | n/a (earlier tool, see last column) | 18401 sets: LZ77 22 ok / 0 failed, Huffman 18378 ok / 1 failed; 1 Huffman set(s) fail with the fixed 65536 and decode with the size of the set |
| 21H2 | 22000.318 | r3 | 2026-10-14 05:53:25+00:00 | 0x230 | 1563/24999 | 22015/352225 | n/a (earlier tool, see last column) | 21965 sets: LZ77 24 ok / 0 failed, Huffman 21940 ok / 1 failed; 1 Huffman set(s) fail with the fixed 65536 and decode with the size of the set |
| 22H2 | 22621.382 | r0 | 2026-10-13 15:50:06+00:00 | 0x230 | 1578/25235 | 18655/298470 | 1 | 18572 sets: LZ77 23 ok / 0 failed, Huffman 18548 ok / 1 failed; 1 Huffman set(s) fail with the fixed 65536 and decode with the size of the set |
| 22H2 | 22621.382 | r1 | generation failed (file not used) |  |  |  |  |  |
| 22H2 | 22621.382 | r2 | 2026-10-14 04:35:58+00:00 | 0x230 | 1577/25218 | 18151/290401 | n/a (earlier tool, see last column) | 18061 sets: LZ77 24 ok / 0 failed, Huffman 18036 ok / 1 failed; 1 Huffman set(s) fail with the fixed 65536 and decode with the size of the set |
| 22H2 | 22621.382 | r3 | 2026-10-14 06:06:13+00:00 | 0x230 | 1577/25232 | 18002/288019 | n/a (earlier tool, see last column) | 17935 sets: LZ77 22 ok / 0 failed, Huffman 17912 ok / 1 failed; 1 Huffman set(s) fail with the fixed 65536 and decode with the size of the set |
| 22H2 | 22621.382 | r4 | 2026-10-14 07:19:56+00:00 | 0x230 | 1576/25210 | 17937/286984 | 1 | 17851 sets: LZ77 24 ok / 0 failed, Huffman 17826 ok / 1 failed; 1 Huffman set(s) fail with the fixed 65536 and decode with the size of the set |
| 23H2 | 22621.2428 | r0 | 2026-10-13 15:53:54+00:00 | 0x230 | 1580/25270 | 18517/296270 | 1 | 18437 sets: LZ77 23 ok / 0 failed, Huffman 18413 ok / 1 failed; 1 Huffman set(s) fail with the fixed 65536 and decode with the size of the set |
| 23H2 | 22621.2428 | r1 | 2026-10-14 03:06:15+00:00 | 0x230 | 1578/25237 | 16745/267919 | 1 | 16646 sets: LZ77 23 ok / 0 failed, Huffman 16622 ok / 1 failed; 1 Huffman set(s) fail with the fixed 65536 and decode with the size of the set |
| 23H2 | 22621.2428 | r2 | 2026-10-14 04:46:37+00:00 | 0x230 | 1578/25235 | 18552/296824 | n/a (earlier tool, see last column) | 18483 sets: LZ77 23 ok / 0 failed, Huffman 18459 ok / 1 failed; 1 Huffman set(s) fail with the fixed 65536 and decode with the size of the set |
| 23H2 | 22621.2428 | r3 | 2026-10-14 06:21:33+00:00 | 0x230 | 1578/25239 | 18931/302894 | n/a (earlier tool, see last column) | 18857 sets: LZ77 22 ok / 0 failed, Huffman 18834 ok / 1 failed; 1 Huffman set(s) fail with the fixed 65536 and decode with the size of the set |
| 24H2 | 26100.1742 | r0 | 2026-10-13 15:57:34+00:00 | 0x238 | 1896/30328 | 19507/312106 | 1 | 19345 sets: LZ77 17 ok / 0 failed, Huffman 19327 ok / 1 failed; 1 Huffman set(s) fail with the fixed 65536 and decode with the size of the set |
| 24H2 | 26100.1742 | r1 | 2026-10-14 03:28:05+00:00 | 0x238 | 1900/30394 | 18847/301546 | 1 | 18701 sets: LZ77 18 ok / 0 failed, Huffman 18682 ok / 1 failed; 1 Huffman set(s) fail with the fixed 65536 and decode with the size of the set |
| 24H2 | 26100.1742 | r2 | generation failed (file not used) |  |  |  |  |  |
| 24H2 | 26100.1742 | r3 | 2026-10-14 06:32:11+00:00 | 0x238 | 1899/30375 | 19638/314207 | n/a (earlier tool, see last column) | 19492 sets: LZ77 18 ok / 0 failed, Huffman 19473 ok / 1 failed; 1 Huffman set(s) fail with the fixed 65536 and decode with the size of the set |
| 24H2 | 26100.1742 | r4 | 2026-10-14 07:41:17+00:00 | 0x238 | 1898/30364 | 19486/311771 | 1 | 19350 sets: LZ77 18 ok / 0 failed, Huffman 19331 ok / 1 failed; 1 Huffman set(s) fail with the fixed 65536 and decode with the size of the set |
| 25H2 | 26100.6584 | r0 | 2026-10-13 16:01:38+00:00 | 0x238 | 2157/34506 | 21630/346065 | 0 | 21183 sets: LZ77 20748 ok / 0 failed, Huffman 435 ok / 0 failed; 0 Huffman set(s) fail with the fixed 65536 and decode with the size of the set |
| 25H2 | 26100.6584 | r1 | 2026-10-14 03:45:56+00:00 | 0x238 | 2153/34439 | 21607/345712 | 0 | 21143 sets: LZ77 20709 ok / 0 failed, Huffman 434 ok / 0 failed; 0 Huffman set(s) fail with the fixed 65536 and decode with the size of the set |
| 25H2 | 26100.6584 | r2 | 2026-10-14 05:21:46+00:00 | 0x238 | 2175/34786 | 21247/339946 | n/a (earlier tool, see last column) | 20763 sets: LZ77 20334 ok / 0 failed, Huffman 429 ok / 0 failed; 0 Huffman set(s) fail with the fixed 65536 and decode with the size of the set |
| 25H2 | 26100.6584 | r3 | 2026-10-14 06:43:46+00:00 | 0x238 | 2148/34362 | 19916/318642 | n/a (earlier tool, see last column) | 19445 sets: LZ77 19044 ok / 0 failed, Huffman 401 ok / 0 failed; 0 Huffman set(s) fail with the fixed 65536 and decode with the size of the set |
| 26H1 | 28000.1340 | r0 | 2026-09-27 19:51:37+00:00 (written at install time, not a generation) | 0x238 | 1980/31669 | 24474/391575 | 0 | 24307 sets: LZ77 23819 ok / 0 failed, Huffman 488 ok / 0 failed; 0 Huffman set(s) fail with the fixed 65536 and decode with the size of the set |
| 26H1 | 28000.1340 | r1 | 2026-10-14 04:03:05+00:00 | 0x238 | 1766/28246 | 26849/429581 | 1 | 26788 sets: LZ77 16 ok / 0 failed, Huffman 26771 ok / 1 failed; 1 Huffman set(s) fail with the fixed 65536 and decode with the size of the set |
| 26H1 | 28000.1340 | r2 | 2026-10-14 05:29:55+00:00 | 0x238 | 1985/31747 | 25695/411106 | n/a (earlier tool, see last column) | 25626 sets: LZ77 17 ok / 0 failed, Huffman 25608 ok / 1 failed; 1 Huffman set(s) fail with the fixed 65536 and decode with the size of the set |
| 26H1 | 28000.1340 | r3 | generation failed (file not used) |  |  |  |  |  |
| 26H1 | 28000.1340 | r4 | 2026-10-14 07:59:15+00:00 | 0x238 | 1987/31785 | 25486/407772 | 1 | 25431 sets: LZ77 17 ok / 0 failed, Huffman 25413 ok / 1 failed; 1 Huffman set(s) fail with the fixed 65536 and decode with the size of the set |

## windows.hibernation.Dump

| build | round | this branch, right --version | second run | original code --version 0 / --version 4 / this branch with the wrong --version |
|---|---|---|---|---|
| 21H2 | r0 | OK, 308394 non-zero pages | identical | v0: ValueError: EOF Error; v4: refused (not converted); wrong --version on the fix: refused (not converted) |
| 21H2 | r1 | OK, 306883 non-zero pages | identical | v0: ValueError: EOF Error; v4: refused (not converted); wrong --version on the fix: refused (not converted) |
| 21H2 | r2 | OK, 307087 non-zero pages | - | v0: -; v4: -; wrong --version on the fix: - |
| 21H2 | r3 | OK, 362847 non-zero pages | - | v0: -; v4: -; wrong --version on the fix: - |
| 22H2 | r0 | OK, 308402 non-zero pages | identical | v0: ValueError: EOF Error; v4: refused (not converted); wrong --version on the fix: refused (not converted) |
| 22H2 | r1 | generation failed (file not used) | | |
| 22H2 | r2 | OK, 301804 non-zero pages | - | v0: -; v4: -; wrong --version on the fix: - |
| 22H2 | r3 | OK, 298952 non-zero pages | - | v0: -; v4: -; wrong --version on the fix: - |
| 22H2 | r4 | OK, 298042 non-zero pages | identical | v0: ValueError: EOF Error; v4: refused (not converted); wrong --version on the fix: refused (not converted) |
| 23H2 | r0 | OK, 308817 non-zero pages | identical | v0: ValueError: EOF Error; v4: refused (not converted); wrong --version on the fix: refused (not converted) |
| 23H2 | r1 | OK, 278116 non-zero pages | identical | v0: ValueError: EOF Error; v4: refused (not converted); wrong --version on the fix: refused (not converted) |
| 23H2 | r2 | OK, 308798 non-zero pages | - | v0: -; v4: -; wrong --version on the fix: - |
| 23H2 | r3 | OK, 313341 non-zero pages | - | v0: -; v4: -; wrong --version on the fix: - |
| 24H2 | r0 | OK, 325586 non-zero pages | identical | v0: refused (not converted); v4: refused (not converted); wrong --version on the fix: refused (not converted) |
| 24H2 | r1 | OK, 313942 non-zero pages | identical | v0: refused (not converted); v4: refused (not converted); wrong --version on the fix: refused (not converted) |
| 24H2 | r2 | generation failed (file not used) | | |
| 24H2 | r3 | OK, 327167 non-zero pages | - | v0: -; v4: -; wrong --version on the fix: - |
| 24H2 | r4 | OK, 325002 non-zero pages | identical | v0: refused (not converted); v4: refused (not converted); wrong --version on the fix: refused (not converted) |
| 25H2 | r0 | OK, 363514 non-zero pages | identical | v0: refused (not converted); v4: refused (not converted); wrong --version on the fix: refused (not converted) |
| 25H2 | r1 | OK, 359170 non-zero pages | identical | v0: refused (not converted); v4: refused (not converted); wrong --version on the fix: refused (not converted) |
| 25H2 | r2 | OK, 355900 non-zero pages | - | v0: -; v4: -; wrong --version on the fix: - |
| 25H2 | r3 | OK, 334667 non-zero pages | - | v0: -; v4: -; wrong --version on the fix: - |
| 26H1 | r0 | OK, 407227 non-zero pages | identical | v0: refused (not converted); v4: refused (not converted); wrong --version on the fix: refused (not converted) |
| 26H1 | r1 | OK, 444349 non-zero pages | identical | v0: refused (not converted); v4: refused (not converted); wrong --version on the fix: refused (not converted) |
| 26H1 | r2 | OK, 427697 non-zero pages | - | v0: -; v4: -; wrong --version on the fix: - |
| 26H1 | r3 | generation failed (file not used) | | |
| 26H1 | r4 | OK, 424453 non-zero pages | identical | v0: refused (not converted); v4: refused (not converted); wrong --version on the fix: refused (not converted) |
