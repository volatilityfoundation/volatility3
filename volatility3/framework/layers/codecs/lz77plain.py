# This file is Copyright 2024 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
import struct, codecs


def lz77_plain_decompress(in_buf):
    """
    Refs :
        - https://learn.microsoft.com/en-us/windows/win32/cmpapi/using-the-compression-api
    """
    out_idx = 0
    in_idx = 0
    nibble_idx = 0

    flags = 0
    flag_count = 0

    out_buf = []

    while in_idx < len(in_buf):
        if flag_count == 0:
            flags = struct.unpack("<I", in_buf[in_idx : in_idx + 4])[0]
            in_idx += 4
            flag_count = 32

        flag_count -= 1

        if (flags & (1 << flag_count)) == 0:
            out_buf.append(in_buf[in_idx])
            in_idx += 1
            out_idx += 1
        else:
            if in_idx == len(in_buf):
                return bytes(out_buf)

            length = struct.unpack("<H", in_buf[in_idx : in_idx + 2])[0]
            in_idx += 2

            offset = (length // 8) + 1
            length = length % 8

            if length == 7:
                if nibble_idx == 0:
                    length = in_buf[in_idx] % 16
                    nibble_idx = in_idx
                    in_idx += 1
                else:
                    length = in_buf[nibble_idx] // 16
                    nibble_idx = 0

                if length == 15:
                    length = in_buf[in_idx]
                    in_idx += 1

                    if length == 255:
                        length = struct.unpack("<H", in_buf[in_idx : in_idx + 2])[0]
                        in_idx += 2

                        if length == 0:
                            length = struct.unpack("<I", in_buf[in_idx : in_idx + 4])[0]
                            in_idx += 4

                        if length < 15 + 7:
                            raise ValueError("CorruptedData")
                        length -= 15 + 7
                    length += 15
                length += 7
            length += 3

            for _ in range(length):
                if offset > out_idx:
                    raise ValueError("CorruptedData")
                out_buf.append(out_buf[out_idx - offset])
                out_idx += 1
    return bytes(out_buf)


class LZ77PlainCodec(codecs.Codec):
    def encode(self, input, errors="strict"):
        raise NotImplementedError("LZ77 plain compression is not implemented")

    def decode(self, input, errors="strict"):
        return lz77_plain_decompress(input), len(input)

    def decode_bytes(self, input):
        return lz77_plain_decompress(input)


class LZ77PlainIncrementalEncoder(codecs.IncrementalEncoder):
    def encode(self, input, final=False):
        raise NotImplementedError("LZ77 plain compression is not implemented")


class LZ77PlainIncrementalDecoder(codecs.IncrementalDecoder):
    def decode(self, input, final=False):
        return lz77_plain_decompress(input)


class LZ77PlainStreamReader(LZ77PlainCodec, codecs.StreamReader):
    def __init__(self, *args, **kwargs):
        codecs.StreamReader.__init__(self, *args, **kwargs)

    def read(self, size=-1, chars=-1, firstline=False):
        data = self.stream.read(size)
        return self.decode_bytes(data)


class LZ77PlainStreamWriter(LZ77PlainCodec, codecs.StreamWriter):
    def write(self, obj):
        raise NotImplementedError("LZ77 plain compression is not implemented")


def find_lz77_plain(name):
    if name == "lz77_plain":
        return codecs.CodecInfo(
            name="lz77_plain",
            encode=LZ77PlainCodec().encode,
            decode=LZ77PlainCodec().decode,
            incrementalencoder=LZ77PlainIncrementalEncoder,
            incrementaldecoder=LZ77PlainIncrementalDecoder,
            streamreader=LZ77PlainStreamReader,
            streamwriter=LZ77PlainStreamWriter,
        )
    return None


codecs.register(find_lz77_plain)
