"""Functions that read AVML files.

The user of the file doesn't have to worry about the compression,
but random access is not allowed."""
import io
import struct
from typing import Tuple, List, Optional

from volatility3.framework import exceptions, interfaces, constants
from volatility3.framework.layers import segmented

try:
    import snappy

    HAS_SNAPPY = True
except ImportError:
    HAS_SNAPPY = False


class SnappyFraming:
    def __init__(self):
        pass

    # crc32-c (Castagnoli) (crc32c_poly=0x1EDC6F41)
    crc32c_table = [
        0x00000000, 0xF26B8303, 0xE13B70F7, 0x1350F3F4,
        0xC79A971F, 0x35F1141C, 0x26A1E7E8, 0xD4CA64EB,
        0x8AD958CF, 0x78B2DBCC, 0x6BE22838, 0x9989AB3B,
        0x4D43CFD0, 0xBF284CD3, 0xAC78BF27, 0x5E133C24,
        0x105EC76F, 0xE235446C, 0xF165B798, 0x030E349B,
        0xD7C45070, 0x25AFD373, 0x36FF2087, 0xC494A384,
        0x9A879FA0, 0x68EC1CA3, 0x7BBCEF57, 0x89D76C54,
        0x5D1D08BF, 0xAF768BBC, 0xBC267848, 0x4E4DFB4B,
        0x20BD8EDE, 0xD2D60DDD, 0xC186FE29, 0x33ED7D2A,
        0xE72719C1, 0x154C9AC2, 0x061C6936, 0xF477EA35,
        0xAA64D611, 0x580F5512, 0x4B5FA6E6, 0xB93425E5,
        0x6DFE410E, 0x9F95C20D, 0x8CC531F9, 0x7EAEB2FA,
        0x30E349B1, 0xC288CAB2, 0xD1D83946, 0x23B3BA45,
        0xF779DEAE, 0x05125DAD, 0x1642AE59, 0xE4292D5A,
        0xBA3A117E, 0x4851927D, 0x5B016189, 0xA96AE28A,
        0x7DA08661, 0x8FCB0562, 0x9C9BF696, 0x6EF07595,
        0x417B1DBC, 0xB3109EBF, 0xA0406D4B, 0x522BEE48,
        0x86E18AA3, 0x748A09A0, 0x67DAFA54, 0x95B17957,
        0xCBA24573, 0x39C9C670, 0x2A993584, 0xD8F2B687,
        0x0C38D26C, 0xFE53516F, 0xED03A29B, 0x1F682198,
        0x5125DAD3, 0xA34E59D0, 0xB01EAA24, 0x42752927,
        0x96BF4DCC, 0x64D4CECF, 0x77843D3B, 0x85EFBE38,
        0xDBFC821C, 0x2997011F, 0x3AC7F2EB, 0xC8AC71E8,
        0x1C661503, 0xEE0D9600, 0xFD5D65F4, 0x0F36E6F7,
        0x61C69362, 0x93AD1061, 0x80FDE395, 0x72966096,
        0xA65C047D, 0x5437877E, 0x4767748A, 0xB50CF789,
        0xEB1FCBAD, 0x197448AE, 0x0A24BB5A, 0xF84F3859,
        0x2C855CB2, 0xDEEEDFB1, 0xCDBE2C45, 0x3FD5AF46,
        0x7198540D, 0x83F3D70E, 0x90A324FA, 0x62C8A7F9,
        0xB602C312, 0x44694011, 0x5739B3E5, 0xA55230E6,
        0xFB410CC2, 0x092A8FC1, 0x1A7A7C35, 0xE811FF36,
        0x3CDB9BDD, 0xCEB018DE, 0xDDE0EB2A, 0x2F8B6829,
        0x82F63B78, 0x709DB87B, 0x63CD4B8F, 0x91A6C88C,
        0x456CAC67, 0xB7072F64, 0xA457DC90, 0x563C5F93,
        0x082F63B7, 0xFA44E0B4, 0xE9141340, 0x1B7F9043,
        0xCFB5F4A8, 0x3DDE77AB, 0x2E8E845F, 0xDCE5075C,
        0x92A8FC17, 0x60C37F14, 0x73938CE0, 0x81F80FE3,
        0x55326B08, 0xA759E80B, 0xB4091BFF, 0x466298FC,
        0x1871A4D8, 0xEA1A27DB, 0xF94AD42F, 0x0B21572C,
        0xDFEB33C7, 0x2D80B0C4, 0x3ED04330, 0xCCBBC033,
        0xA24BB5A6, 0x502036A5, 0x4370C551, 0xB11B4652,
        0x65D122B9, 0x97BAA1BA, 0x84EA524E, 0x7681D14D,
        0x2892ED69, 0xDAF96E6A, 0xC9A99D9E, 0x3BC21E9D,
        0xEF087A76, 0x1D63F975, 0x0E330A81, 0xFC588982,
        0xB21572C9, 0x407EF1CA, 0x532E023E, 0xA145813D,
        0x758FE5D6, 0x87E466D5, 0x94B49521, 0x66DF1622,
        0x38CC2A06, 0xCAA7A905, 0xD9F75AF1, 0x2B9CD9F2,
        0xFF56BD19, 0x0D3D3E1A, 0x1E6DCDEE, 0xEC064EED,
        0xC38D26C4, 0x31E6A5C7, 0x22B65633, 0xD0DDD530,
        0x0417B1DB, 0xF67C32D8, 0xE52CC12C, 0x1747422F,
        0x49547E0B, 0xBB3FFD08, 0xA86F0EFC, 0x5A048DFF,
        0x8ECEE914, 0x7CA56A17, 0x6FF599E3, 0x9D9E1AE0,
        0xD3D3E1AB, 0x21B862A8, 0x32E8915C, 0xC083125F,
        0x144976B4, 0xE622F5B7, 0xF5720643, 0x07198540,
        0x590AB964, 0xAB613A67, 0xB831C993, 0x4A5A4A90,
        0x9E902E7B, 0x6CFBAD78, 0x7FAB5E8C, 0x8DC0DD8F,
        0xE330A81A, 0x115B2B19, 0x020BD8ED, 0xF0605BEE,
        0x24AA3F05, 0xD6C1BC06, 0xC5914FF2, 0x37FACCF1,
        0x69E9F0D5, 0x9B8273D6, 0x88D28022, 0x7AB90321,
        0xAE7367CA, 0x5C18E4C9, 0x4F48173D, 0xBD23943E,
        0xF36E6F75, 0x0105EC76, 0x12551F82, 0xE03E9C81,
        0x34F4F86A, 0xC69F7B69, 0xD5CF889D, 0x27A40B9E,
        0x79B737BA, 0x8BDCB4B9, 0x988C474D, 0x6AE7C44E,
        0xBE2DA0A5, 0x4C4623A6, 0x5F16D052, 0xAD7D5351,
    ]

    def masked_crc32c(self, buf: bytes) -> int:
        crc = 0xffffffff
        for c in buf:
            crc = (crc >> 8) ^ self.crc32c_table[(crc ^ c) & 0xFF]
        crc = (~crc) & 0xffffffff
        # reverse endianness
        crc = struct.unpack(">I", struct.pack("<I", crc))[0]
        return (((crc >> 15) | (crc << 17)) + 0xa282ead8) & 0xffffffff

    def decompress(self, source_data: bytes) -> io.BytesIO:
        offset = 0
        data = io.BytesIO()
        while offset < len(source_data):
            header_structure = "<IIQQQ"
            header_size = struct.calcsize(header_structure)
            header_data = source_data[offset:offset + header_size]
            magic, version, start, end, padding = struct.unpack(header_structure, header_data)
            print(magic, version, start, end, padding)
            if magic not in [0x4c4d5641]:
                raise RuntimeError("File not in AVML or LiME format")
            chunk_data = source_data[offset + header_size: offset + header_size + (end - start)]
            chunk, consumed = self.read_snappy_data(chunk_data, end - start)
            data.seek(start)
            data.write(chunk)
            # TODO: Check whatever the remaining 8 bytes are
            offset += header_size + consumed + 8
        data.seek(0)
        return data

    def read_snappy_data(self, data: bytes, limit: int) -> Tuple[bytes, int]:
        """Decompresses data up to the size limit provided

        Args:
            data: Input data
            limit: The maximum size of decompressed data

        Returns:
            Tuple of decompressed data, and number of compressed bytes consumed
        """
        decompressed = bytearray()
        offset = 0
        crc_len = 4
        chunk_header_struct = '<L'
        chunk_header_len = struct.calcsize(chunk_header_struct)
        while len(decompressed) <= limit:
            if offset + chunk_header_len < len(data):
                chunk_header = data[offset:offset + chunk_header_len]
                chunk_header_val = struct.unpack('<L', chunk_header)[0]
                chunk_type, chunk_size = chunk_header_val & 0xff, chunk_header_val >> 8
                if chunk_type == 0xff:
                    if data[offset + chunk_header_len:offset + chunk_header_len + chunk_size] != b'sNaPpY':
                        raise ValueError(f"Snappy header missing at offset: {offset}")
                elif chunk_type in [0x00, 0x01]:
                    # CRC + (Un)compressed data
                    start = offset + chunk_header_len
                    chunk_crc = data[start: start + crc_len]
                    chunk_data = data[start + crc_len: start + chunk_size]
                    if chunk_type == 0x00:
                        # Compressed data
                        chunk_data = snappy.decompress(chunk_data)
                    # TODO: Verify CRC
                    decompressed.extend(chunk_data)
                elif chunk_type in range(0x2, 0x80):
                    # Unskippable
                    raise ValueError(f"Unskippable chunk of type {chunk_type} found: {offset}")
                offset += chunk_header_len + chunk_size
        return decompressed, offset


class AVMLLayer(segmented.NonLinearlySegmentedLayer):
    """A Lime format TranslationLayer.

    Lime is generally used to store physical memory images where there
    are large holes in the physical layer
    """

    def __init__(self, *args, **kwargs):
        self._compressed = {}
        super().__init__(*args, **kwargs)

    @classmethod
    def _check_header(cls, layer: interfaces.layers.DataLayerInterface):
        header_structure = "<II"
        magic, version = struct.unpack(header_structure,
                                       layer.read(layer.minimum_address, struct.calcsize(header_structure)))
        if magic not in [0x4c4d5641] or version != 2:
            raise exceptions.LayerException("File not completely in AVML format")

    def _load_segments(self) -> None:
        base_layer = self.context.layers[self._base_layer]
        offset = base_layer.minimum_address
        while offset + 4 < base_layer.maximum_address:
            avml_header_structure = "<IIQQQ"
            avml_header_size = struct.calcsize(avml_header_structure)
            avml_header_data = base_layer.read(offset, avml_header_size)
            magic, version, start, end, padding = struct.unpack(avml_header_structure, avml_header_data)

            if magic not in [0x4c4d5641] or version != 2:
                raise exceptions.LayerException("File not completely in AVML format")
            chunk_data = base_layer.read(offset + avml_header_size,
                                         min(end - start,
                                             base_layer.maximum_address - (offset + avml_header_size)))
            segments, consumed = self._read_snappy_frames(chunk_data, end - start)
            # The returned segments are accurate the chunk_data that was passed in, but needs shifting
            for (thing, mapped_offset, size, mapped_size, compressed) in segments:
                self._segments.append((thing + start, offset + mapped_offset + avml_header_size, size, mapped_size))
                self._compressed[offset + mapped_offset + avml_header_size] = compressed

            # TODO: Check whatever the remaining 8 bytes are
            offset += avml_header_size + consumed + 8

    def _read_snappy_frames(self, data: bytes, expected_length: int) -> Tuple[
        List[Tuple[int, int, int, int, bool]], int]:
        """
        Reads a framed-format snappy stream

        Args:
            data: The stream to read
            expected_length: How big the decompressed stream is expected to be (termination limit)

        Returns:
            (offset, mapped_offset, length, mapped_length, compressed) relative to the data chunk (ie, not relative to the file start)
        """
        segments = []
        decompressed_len = 0
        offset = 0
        crc_len = 4
        frame_header_struct = '<L'
        frame_header_len = struct.calcsize(frame_header_struct)
        while decompressed_len <= expected_length:
            if offset + frame_header_len < len(data):
                frame_header = data[offset:offset + frame_header_len]
                frame_header_val = struct.unpack('<L', frame_header)[0]
                frame_type, frame_size = frame_header_val & 0xff, frame_header_val >> 8
                if frame_type == 0xff:
                    if data[offset + frame_header_len:offset + frame_header_len + frame_size] != b'sNaPpY':
                        raise ValueError(f"Snappy header missing at offset: {offset}")
                elif frame_type in [0x00, 0x01]:
                    # CRC + (Un)compressed data
                    mapped_start = offset + frame_header_len
                    frame_crc = data[mapped_start: mapped_start + crc_len]
                    frame_data = data[mapped_start + crc_len: mapped_start + frame_size]
                    if frame_type == 0x00:
                        # Compressed data
                        frame_data = snappy.decompress(frame_data)
                    # TODO: Verify CRC
                    segments.append((decompressed_len, mapped_start + crc_len, len(frame_data), frame_size - crc_len,
                                     frame_type == 0x00))
                    decompressed_len += len(frame_data)
                elif frame_type in range(0x2, 0x80):
                    # Unskippable
                    raise exceptions.LayerException(f"Unskippable chunk of type {frame_type} found: {offset}")
                offset += frame_header_len + frame_size
        return segments, offset

    def _decode_data(self, data: bytes, mapped_offset: int, offset: int, output_length: int) -> bytes:
        start_offset, _, _, _ = self._find_segment(offset)
        if self._compressed[mapped_offset]:
            decoded_data = snappy.decompress(data)
        else:
            decoded_data = data
        decoded_data = decoded_data[offset - start_offset:]
        decoded_data = decoded_data[:output_length]
        return decoded_data


class AVMLStacker(interfaces.automagic.StackerLayerInterface):
    stack_order = 10

    @classmethod
    def stack(cls,
              context: interfaces.context.ContextInterface,
              layer_name: str,
              progress_callback: constants.ProgressCallback = None) -> Optional[interfaces.layers.DataLayerInterface]:
        try:
            AVMLLayer._check_header(context.layers[layer_name])
        except exceptions.LayerException:
            return None
        new_name = context.layers.free_layer_name("AVMLLayer")
        context.config[interfaces.configuration.path_join(new_name, "base_layer")] = layer_name
        return AVMLLayer(context, new_name, new_name)


if __name__ == '__main__':
    import sys

    source_data = open(sys.argv[1], 'br').read()

    sf = SnappyFraming()
    with open('outputfile', 'wb') as fp:
        fp.write(sf.decompress(source_data).read())
