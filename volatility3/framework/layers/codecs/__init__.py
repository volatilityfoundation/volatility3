# This file is Copyright 2022 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

"""Codecs used for encoding or decoding data should live here
"""
import io, struct

def encoded_bit_length(data, symbol):
    if (symbol % 2) == 0:
        return int(data[symbol//2] & 0x0f)
    else:
        return int(data[symbol//2] >> 4)

def Read16Bits(input, current_position):
    return (input[current_position] << 8) | input[current_position + 1]

def ReadByte(input, current_position):
    stream = io.BytesIO(input)
    stream.seek(current_position)
    return int.from_bytes(stream.read(1),"little")

def lz77_huffman_decompress(compressed_input):
    decoding_table = [0]*pow(2,15)
    current_table_entry = 0

    for bit_length in range(1, 16):
        for symbol in range(0, 512):
            if encoded_bit_length(compressed_input[0:256],symbol) == bit_length:
                entry_count = 1 << (15 - bit_length)
                for _ in range(entry_count):
                    if current_table_entry >= pow(2,15):
                        raise ValueError("The compressed data is not valid.")
                    decoding_table[current_table_entry] = symbol
                    current_table_entry += 1
        if current_table_entry != pow(2,15):
            raise ValueError("The compressed data is not valid.")

    output_buffer = []
    current_position = 256
    next_bits = Read16Bits(compressed_input,current_position)
    current_position += 2
    next_bits <<= 16
    next_bits |= Read16Bits(compressed_input,current_position)
    current_position += 2
    extra_bit_count = 16
    block_end = len(output_buffer) + 65536

    while True:
        # Start of new block
        if current_position + 512 > len(compressed_input):
            print("EOF reached. Terminating decoding.")
            return output_buffer
        if len(output_buffer) >= block_end:
            break
        next_15bits = next_bits >> (32 - 15)
        huffman_symbol = decoding_table[next_15bits]
        huffman_symbol_bit_length = encoded_bit_length(compressed_input[0:256],huffman_symbol)

        next_bits <<= huffman_symbol_bit_length
        extra_bit_count -= huffman_symbol_bit_length

        if extra_bit_count < 0:
            next_bits |= Read16Bits(compressed_input,current_position) << (-extra_bit_count)
            extra_bit_count += 16
            current_position += 2

        if huffman_symbol < 256:
            output_buffer.append(huffman_symbol)

        elif huffman_symbol == 256 and current_position == len(compressed_input):
            return output_buffer

        else:
            huffman_symbol -= 256
            match_length = huffman_symbol % 16
            match_offset_bit_length = huffman_symbol // 16
            if match_length == 15:
                match_length = ReadByte(compressed_input,current_position)
                current_position += 1
                if match_length == 255:
                    match_length = Read16Bits(compressed_input,current_position)
                    current_position += 2
                    if match_length < 15:
                        raise ValueError("The compressed data is invalid.")
                    match_length -= 15
                match_length += 15
            match_length += 3
            match_offset = next_bits >> (32 - match_offset_bit_length)
            match_offset += pow(2, match_offset_bit_length)
            next_bits <<= match_offset_bit_length
            extra_bit_count -= match_offset_bit_length
            if extra_bit_count < 0:
                next_bits |= Read16Bits(compressed_input,current_position) << (-extra_bit_count)
                extra_bit_count += 16
                current_position += 2
            for i in range(match_length):
                output_buffer.append(output_buffer[len(output_buffer) - match_offset + i])

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

