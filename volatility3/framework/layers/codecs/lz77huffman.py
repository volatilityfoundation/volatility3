# This file is Copyright 2024 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0

import struct, logging, codecs
from typing import Tuple, List, Union

vollog = logging.getLogger(__name__)


class BitStream:
    def __init__(self, source: bytes, in_pos: int):
        self.source = source
        self.index = in_pos + 4
        # read UInt16 little endian
        mask = struct.unpack_from("<H", source, in_pos)[0] << 16
        mask += struct.unpack_from("<H", source, in_pos + 2)[0]
        self.mask = mask
        self.bits = 32

    def lookup(self, n: int) -> int:
        if n == 0:
            return 0
        return self.mask >> (32 - n)

    def skip(self, n: int) -> Union[None, Exception]:
        self.mask = (self.mask << n) & 0xFFFFFFFF
        self.bits -= n
        if self.bits < 16:
            if self.index + 2 > len(self.source):
                return Exception("EOF Error")
            # read UInt16 little endian
            self.mask += (
                (struct.unpack_from("<H", self.source, self.index)[0])
                << (16 - self.bits)
            ) & 0xFFFFFFFF
            self.index += 2
            self.bits += 16

        return None

    def __str__(self):
        return f"{self.id}: symbol {self.symbol} length {self.length}"


class PREFIX_CODE_NODE:
    def __init__(self):
        self.id = 0
        self.symbol = 0
        self.leaf = False
        self.child = [None, None]

    def __str__(self):
        return f"Node {self.id}: symbol {self.symbol} leaf {self.leaf}"


class PREFIX_CODE_SYMBOL:
    def __init__(self):
        self.id = 0
        self.symbol = 0
        self.length = 0

    def __str__(self):
        return f"Symbol {self.id}: symbol {self.symbol} length {self.length}"


def prefix_code_tree_add_leaf(
    treeNodes: List[PREFIX_CODE_NODE], leafIndex: int, mask: int, bits: int
) -> int:
    node = treeNodes[0]
    i = leafIndex + 1
    childIndex = None

    while bits > 1:
        bits -= 1
        childIndex = (mask >> bits) & 1
        if not node.child[childIndex]:
            node.child[childIndex] = treeNodes[i]
            treeNodes[i].leaf = False
            i += 1
        node = node.child[childIndex]

    node.child[mask & 1] = treeNodes[leafIndex]

    return i


def prefix_code_tree_rebuild(input: bytes) -> PREFIX_CODE_NODE:
    treeNodes = [PREFIX_CODE_NODE() for _ in range(1024)]
    symbolInfo = [PREFIX_CODE_SYMBOL() for _ in range(512)]

    for i in range(256):
        value = input[i]

        symbolInfo[2 * i].id = 2 * i
        symbolInfo[2 * i].symbol = 2 * i
        symbolInfo[2 * i].length = value & 0xF

        value >>= 4

        symbolInfo[2 * i + 1].id = 2 * i + 1
        symbolInfo[2 * i + 1].symbol = 2 * i + 1
        symbolInfo[2 * i + 1].length = value & 0xF

    symbolInfo = sorted(symbolInfo, key=lambda x: (x.length, x.symbol))

    i = 0
    while i < 512 and symbolInfo[i].length == 0:
        i += 1

    mask = 0
    bits = 1

    root = treeNodes[0]
    root.leaf = False

    j = 1
    while i < 512:
        treeNodes[j].id = j
        treeNodes[j].symbol = symbolInfo[i].symbol
        treeNodes[j].leaf = True
        mask = mask << (symbolInfo[i].length - bits)
        bits = symbolInfo[i].length
        j = prefix_code_tree_add_leaf(treeNodes, j, mask, bits)
        mask += 1
        i += 1

    return root


def prefix_code_tree_decode_symbol(
    bstr: BitStream, root: PREFIX_CODE_NODE
) -> Tuple[int, Union[None, Exception]]:
    node = root
    while True:
        bit = bstr.lookup(1)
        err = bstr.skip(1)
        if err is not None:
            vollog.warning("Some data could not be decompressed.")
            return 0, err

        node = node.child[bit]
        if not node:
            vollog.warning("Corruption detected when decompressing the data.")
            return 0, Exception("Corruption detected")
        if node.leaf:
            break
    return node.symbol, None


class Lz77HuffmanCodec:
    def encode(self, input: bytes, errors: str = "strict") -> Tuple[bytes, int]:
        raise NotImplementedError("Encoding not implemented for LZ77 Huffman.")

    def decode(self, input: bytes, errors: str = "strict") -> Tuple[bytes, int]:
        output_size = 65536
        output, err = self.lz77_huffman_decompress(input, output_size)
        if err is not None:
            raise Exception(f"Decoding failed: {err}")
        return output, len(input)

    @staticmethod
    def lz77_huffman_decompress(
        input: bytes, output_size: int
    ) -> Tuple[bytes, Union[None, Exception]]:
        output = bytearray(output_size)
        err = None

        # Index into the input buffer.
        in_idx = 0

        # Index into the output buffer.
        out_idx = 0

        while True:
            # How much data belongs in the current chunk.
            # Chunks are split into maximum 65536 bytes.
            chunk_size = output_size - out_idx
            if chunk_size > 65536:
                chunk_size = 65536

            in_idx, out_idx, err = Lz77HuffmanCodec.lz77_huffman_decompress_chunk(
                in_idx, input, out_idx, output, chunk_size
            )
            if err is not None:
                return bytes(output), err
            if out_idx >= len(output) or in_idx >= len(input):
                break
        return bytes(output), None

    @staticmethod
    def lz77_huffman_decompress_chunk(
        in_idx: int, input: bytes, out_idx: int, output: bytearray, chunk_size: int
    ) -> Tuple[int, int, Union[None, Exception]]:
        if in_idx + 256 > len(input):
            return 0, 0, Exception("EOF Error")

        root = prefix_code_tree_rebuild(input[in_idx:])
        bstr = BitStream(input, in_idx + 256)

        i = out_idx

        while i < out_idx + chunk_size:
            symbol, err = prefix_code_tree_decode_symbol(bstr, root)

            if err is not None:
                return int(bstr.index), i, err

            if symbol < 256:
                output[i] = symbol
                i += 1
            else:
                symbol -= 256
                length = symbol & 15
                symbol >>= 4

                offset = 0
                if symbol != 0:
                    offset = int(bstr.lookup(symbol))

                offset |= 1 << symbol
                offset = -offset

                if length == 15:
                    length = bstr.source[bstr.index] + 15
                    bstr.index += 1

                    if length == 270:
                        length = struct.unpack_from("<H", bstr.source, bstr.index)[0]
                        bstr.index += 2

                err = bstr.skip(symbol)
                if err is not None:
                    return int(bstr.index), i, err

                length += 3
                while length > 0:
                    if i + offset < 0:
                        vollog.warning("Some data could not be decompressed.")
                        return int(bstr.index), i, Exception("Decompression Error")

                    output[i] = output[i + offset]
                    i += 1
                    length -= 1
                    if length == 0:
                        break
        return int(bstr.index), i, None


class Lz77HuffmanIncrementalEncoder(codecs.IncrementalEncoder):
    def encode(self, input, final=False):
        raise NotImplementedError(
            "Incremental encoding not implemented for LZ77 Huffman."
        )


class Lz77HuffmanIncrementalDecoder(codecs.IncrementalDecoder):
    def decode(self, input, final=False):
        codec = Lz77HuffmanCodec()
        output, _ = codec.decode(input)
        return output


class Lz77HuffmanStreamReader(codecs.StreamReader):
    def decode(self, input, errors="strict"):
        codec = Lz77HuffmanCodec()
        output, _ = codec.decode(input, errors)
        return output, len(input)


class Lz77HuffmanStreamWriter(codecs.StreamWriter):
    def encode(self, input, errors="strict"):
        codec = Lz77HuffmanCodec()
        return codec.encode(input, errors)


# Codec search function
def find_lz77_huffman(name):
    if name == "lz77_huffman":
        return codecs.CodecInfo(
            name="lz77_huffman",
            encode=Lz77HuffmanCodec().encode,
            decode=Lz77HuffmanCodec().decode,
            incrementalencoder=Lz77HuffmanIncrementalEncoder,
            incrementaldecoder=Lz77HuffmanIncrementalDecoder,
            streamreader=Lz77HuffmanStreamReader,
            streamwriter=Lz77HuffmanStreamWriter,
        )
    return None
