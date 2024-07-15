# This file is Copyright 2024 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
import codecs

from volatility3.framework.layers.codecs.lz77plain import find_lz77_plain
from volatility3.framework.layers.codecs.lz77huffman import find_lz77_huffman

codecs.register(find_lz77_plain)
codecs.register(find_lz77_huffman)
# Register other codecs here.
