#!/usr/bin/env python3
"""Tests of the real Volatility hibernation layer (volatility3/framework/layers/hib.py) on small
synthetic hiberfil.sys files. No sample data: the files come from the builders of test_hib_layout.py.

What is checked, for every layout seen in Windows 11 hibernation files:
  - the layer finds the KernelPagesProcessed counter (0x230 for 21H2-23H2 with --version 0,
    0x238 or 0x250 for build 26100 with --version 4, found by walking the chain of compression sets),
  - every page of the boot and of the kernel section reads back exactly as it was encoded,
  - this includes a Huffman set that covers fewer than 16 pages (4 pages here), which is
    what the real Windows 11 21H2, 22H2, 23H2 and 24H2 files hold at the end of the kernel section.
    With the decoder asked for a fixed 65536 bytes such a set fails with "EOF Error".

Run from the root of the repository (needs `pip install xpress-lz77`, skipped otherwise):
    python3 -m unittest -v contrib.hibernation_checks.test_hib_layer
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))

import test_hib_layout as t  # noqa: E402

try:
    import xpress_lz77  # noqa: F401

    from volatility3.framework import contexts, exceptions
    from volatility3.framework.layers import hib, physical

    HAVE_LAYER = hasattr(hib, "HibernationLayer")
except ImportError:  # pragma: no cover
    HAVE_LAYER = False

PAGE = t.PAGE
BIT31 = t.BIT31

# (name of the layout in hib_check.py, --version of windows.hibernation.Dump, extra header bits of a
# Huffman set: the 23H2 rules need bit 31, the 24H2 rules only bit 30)
LAYOUTS = [
    ("23h2", 0, BIT31),
    ("24h2-early", 4, 0),
    ("24h2", 4, 0),
]


def kernel_specs(huffman_bits):
    return [
        ("plain", 300, 4, 0),
        ("huffman", 320, 16, huffman_bits),
        ("raw", 340, 2, 0),
        ("plain", 350, 3, 0),
        # the end of the section: a Huffman set of 4 pages, not 16
        ("huffman", 360, 4, huffman_bits),
    ]


@unittest.skipUnless(HAVE_LAYER, "needs xpress-lz77 and the volatility3 framework")
class HibernationLayerOnSyntheticFiles(unittest.TestCase):
    def _layer(self, synth, version):
        context = contexts.Context()
        context.config["plugins.Dump.version"] = version
        base = physical.BufferDataLayer(context, "base_cfg", "base", synth.data)
        context.add_layer(base)
        context.config["HibernationLayer.base_layer"] = "base"
        return hib.HibernationLayer(context, "HibernationLayer", "HibernationLayer")

    def test_every_page_reads_back(self):
        for layout, version, huffman_bits in LAYOUTS:
            with self.subTest(layout=layout, version=version):
                boot = [("plain", 100, 3, 0), ("raw", 110, 2, 0)]
                synth = t.Synth(boot, kernel_specs(huffman_bits), layout=layout)
                layer = self._layer(synth, version)
                self.assertGreater(len(synth.decoded), 0)
                for pfn, page in synth.decoded.items():
                    self.assertEqual(
                        layer.read(pfn * PAGE, PAGE),
                        page,
                        f"page {pfn} does not read back",
                    )

    def test_small_huffman_set_does_not_abort_the_conversion(self):
        # the failure seen on real files: the decoder asked for 65536 bytes on a 4-page set
        for layout, version, huffman_bits in LAYOUTS:
            with self.subTest(layout=layout):
                synth = t.Synth(
                    [("plain", 100, 3, 0)],
                    [("huffman", 300, 4, huffman_bits)],
                    layout=layout,
                )
                layer = self._layer(synth, version)
                for pfn in range(300, 304):
                    self.assertEqual(layer.read(pfn * PAGE, PAGE), synth.decoded[pfn])

    def test_wrong_counter_offset_is_refused_for_24h2(self):
        # a 24H2 file whose counter is at none of the known offsets must be refused, not guessed
        synth = t.Synth([("plain", 100, 3, 0)], kernel_specs(0), layout="24h2")
        data = bytearray(synth.data)
        off = t.hc.KPP_OFF["24h2"]
        data[off : off + 8] = (12345).to_bytes(8, "little")
        synth.data = bytes(data)
        with self.assertRaises(exceptions.LayerException):
            self._layer(synth, 4)


if __name__ == "__main__":
    unittest.main()
