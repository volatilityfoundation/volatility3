# This file is Copyright 2022 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

"""Codecs used for encoding or decoding data should live here
"""
import io, struct, numpy

def encoded_bit_length(data, symbol):
    if (symbol % 2) == 0:
        return int(data[symbol//2] & 0x0f)
    else:
        return int(data[symbol//2] >> 4)

def Read16Bits(input, current_position):
    if current_position > len(input):
        print("Incomplete Prefetch")
        exit(1)
    stream = io.BytesIO(input)
    stream.seek(current_position)
    byte_value = bytearray(stream.read(2))
    val = numpy.uint16(0)
    j = 0
    for i in byte_value:
        val = val | (numpy.uint16(i) << numpy.uint(j*8))
        j = j+1
    return val

def ReadByte(input, current_position):
    stream = io.BytesIO(input)
    stream.seek(current_position)
    return int.from_bytes(stream.read(1),"little")

def lz77_huffman_decompress(in_buf):
    """
    Description : Decompress the prefetch using LZ77+Huffman Decompression Algorithm
    Params :
        @data : The compressed prefetch data extracted from memory
        @result : The uncompressed prefetch file ready to be forensically analysed
    Possible errors :
        Invalid compressed data.
    """
    if len(in_buf) < 256:
        print("Error : The prefetch must use a 256-byte Huffman table. -> Invalid data")

    #First, we construct our Huffman decoding table
    decoding_table = [0] * (2**15)
    current_table_entry = 0
    encoded_data = in_buf[0:256]
    for bit_length in range(1,16):
        for symbol in range(0, 512):
            if encoded_bit_length(encoded_data, symbol) == bit_length: # If the encoded bit length of symbol equals bit_length
                entry_count = (1 << (15 - bit_length))
                for i in range(0, entry_count):
                    if current_table_entry >= 2**15: #Huffman table length
                        raise ValueError('CorruptedData')
                    decoding_table[current_table_entry] = numpy.uint16(symbol)
                    current_table_entry += 1
    if current_table_entry != 2**15:
        raise ValueError('CorruptedData')


    #Then, it's time to decompress the data
    """
    The compression stream is designed to be read in (mostly) 16-bit chunks, with a 32-bit register
    maintaining at least the next 16 bits of input. This strategy allows the code to seamlessly handle the
    bytes for long match lengths, which would otherwise be awkward.
    """
    out_buf = []
    input_buffer = in_buf
    current_position = 256 # start at the end of the Huffman table
    next_bits = Read16Bits(input_buffer, current_position)
    current_position += 2
    next_bits = numpy.uint32(next_bits) <<  numpy.int64(16)
    next_bits = next_bits | numpy.uint32(Read16Bits(input_buffer, current_position))
    current_position += 2
    extra_bit_count = 16
    # Loop until a block terminating condition
    while True:
        next_15_bits = numpy.uint32(next_bits) >> numpy.uint32((32 - 15))
        huffman_symbol = decoding_table[next_15_bits]
        huffman_symbol_bit_length = encoded_bit_length(encoded_data, huffman_symbol)
        next_bits = numpy.int32(next_bits << huffman_symbol_bit_length)
        extra_bit_count -= huffman_symbol_bit_length
        if extra_bit_count < 0:
            next_bits = next_bits | (numpy.uint32(Read16Bits(input_buffer, current_position)) << (-extra_bit_count))
            current_position += 2
            extra_bit_count += 16
        if huffman_symbol < 256:
            out_buf.append(huffman_symbol)
        elif huffman_symbol == 256 and (len(input_buffer) - current_position) == 0:
            return bytes(out_buf)
        else:
            huffman_symbol = huffman_symbol - 256
            match_length = huffman_symbol % 16
            match_offset_bit_length = huffman_symbol // 16
            if match_length == 15:
                match_length = numpy.uint16(ReadByte(input_buffer, current_position))
                current_position+=1
                if match_length == 255:
                    match_length = Read16Bits(input_buffer, current_position)
                    current_position += 2
                    if match_length < 15:
                        raise ValueError('CorruptedData')
                    match_length -= 15
                match_length += 15
            match_length += 3
            match_offset = next_bits >> (32 - match_offset_bit_length)
            match_offset += (1 << match_offset_bit_length)
            next_bits = next_bits << match_offset_bit_length
            extra_bit_count -= match_offset_bit_length
            if extra_bit_count < 0:
                next_bits = next_bits | (numpy.uint32(Read16Bits(input_buffer, current_position)) << (-extra_bit_count))
                current_position += 2
                extra_bit_count += 16
            for _ in range(0, match_length):
                to_write = out_buf[(len(out_buf)-1) - int(match_offset)]
                out_buf.append(to_write)

def lz77_plain_decompress(in_buf):
    out_idx = 0
    in_idx = 0
    nibble_idx = 0

    flags = 0
    flag_count = 0

    out_buf = []

    while in_idx < len(in_buf):
        if flag_count == 0:
            flags = struct.unpack('<I', in_buf[in_idx:in_idx+4])[0]
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
            
            length = struct.unpack('<H', in_buf[in_idx:in_idx+2])[0]
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
                        length = struct.unpack('<H', in_buf[in_idx:in_idx+2])[0]
                        in_idx += 2

                        if length == 0:
                            length = struct.unpack('<I', in_buf[in_idx:in_idx+4])[0]
                            in_idx += 4

                        if length < 15 + 7:
                            raise ValueError('CorruptedData')
                        length -= 15 + 7
                    length += 15
                length += 7
            length += 3

            for _ in range(length):
                if offset > out_idx:
                    raise ValueError('CorruptedData')
                out_buf.append(out_buf[out_idx - offset])
                out_idx += 1

    return bytes(out_buf)

