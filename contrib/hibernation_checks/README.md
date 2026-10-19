# Checks for the hibernation layer (Windows 11 24H2+ support, Huffman set size)

Plain Python 3 scripts, no Volatility needed for the first three. They print counters only (no path,
no hash, no exact file size, no section offset by default). For the decompression checks and the
layer tests: `pip install xpress-lz77`.

| file | what it does |
|---|---|
| `hib_check.py` | Walks the chain of compression sets of the boot and of the kernel section of a `hiberfil.sys` with three layouts: `23h2` (size = bits 8-29, bits 30-31 = algorithm, `KernelPagesProcessed` at `0x230`), `24h2-early` (size = bits 8-28, bit 30 = LZ77+Huffman, counter at `0x238`) and `24h2` (same rules, counter at `0x250`). A layout matches a section when the chain reaches exactly the page count of the header with no invalid set header. It also walks the kernel chain until it ends by itself and prints which header qwords hold its page count and byte length (to find the counter of an unknown build), the set kinds and header bits 25-31 of each section, the Huffman sets that do not cover 16 pages, and with `--decompress` decompresses every compressed set and checks the output size. `--show-offsets` adds identifying values (local debugging only). |
| `compare_outputs.py` | Compares two `windows.hibernation.Dump` outputs of the same file page by page, for the pages of the boot section and of the kernel section (`--outside` also counts the pages outside both). |
| `count_nonzero_pages.py` | Counts the 4 KiB pages of a raw image that contain a non-zero byte (needs numpy). |
| `test_hib_layout.py` | 16 synthetic unit tests of the tools, on hibernation files generated in memory. No sample data. |
| `test_hib_layer.py` | 3 tests of the real `HibernationLayer` on the same synthetic files, for the three layouts: every page reads back; a LZ77+Huffman set of 4 pages converts (with the decoder asked for a fixed 65536 bytes it fails with `EOF Error`); a `--version 4` file whose counter matches no known offset is refused. Needs `xpress-lz77` and runs from this directory with the repository root on `sys.path` (done by the test itself). |
| `campaign_2026-10/` | Logs of the test campaign on Windows 11 21H2, 22H2, 23H2, 24H2, 25H2 and 26H1 lab VMs: `SUMMARY.md` (tables), `campaign.log` (one line per step), and per build and round the `hib_check.py --decompress` output and the `windows.hibernation.Dump` runs (this branch, second run, original code, wrong `--version`), the unit-test and ruff runs. Nothing from a real case is included. |

```
python3 hib_check.py hiberfil.sys --decompress
python3 compare_outputs.py hiberfil.sys out_a/memory_layer.raw out_b/memory_layer.raw
cd contrib/hibernation_checks && python3 -m unittest -v test_hib_layout test_hib_layer
```

The two tools mirror the parsing rules of the layer, they are not Volatility itself; `test_hib_layer.py`
exercises the layer.
