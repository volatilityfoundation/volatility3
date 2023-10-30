from typing import Optional
import logging, struct
from volatility3.framework import interfaces, constants, exceptions
from volatility3.framework.layers import segmented
from volatility3.framework.renderers import conversion
from volatility3.framework.layers.codecs import lz77_plain_decompress, lz77_huffman_decompress


vollog = logging.getLogger(__name__)


def uncompress(data: bytes, huffman, out_size):
    if huffman == 0:
        return lz77_plain_decompress(data)
    elif huffman == 2 or huffman == 3:
        return lz77_huffman_decompress(data,out_size)[0]
    else: 
        raise ValueError('Cannot decompress the data.')


def readBytes(data, position, num):
    end = position + num
    byte_vals = data[position:end]
    return int.from_bytes(byte_vals, byteorder='big')

class HibernationFileException(exceptions.LayerException):
    """Thrown when an error occurs with the underlying Hibernation file format."""

class HibernationLayer(segmented.NonLinearlySegmentedLayer):
    """
    A TranslationLayer that maps physical memory against a Microsoft Windows hibernation file (x64 only for now).
    """
    PAGE_SIZE = 4096
    HEADER_SIZE = 4
    PAGE_DESC_SIZE = 8
    def __init__(self, context: interfaces.context.ContextInterface, config_path: str, name: str, **kwargs):
        """
        Initializes the Hibernation file layer.
        """
        # Call the superclass constructor.
        self._compressed = {}
        self._mapping = {}
        super().__init__(context, config_path, name, **kwargs)

    @classmethod
    def _check_header(
        cls, base_layer: interfaces.layers.DataLayerInterface, name: str = ""
    ):
        header = base_layer.read(0, 4)
        if header != b'HIBR':
            raise exceptions.LayerException(name, "No Hibernation magic bytes")
        else: 
            vollog.info("Detecting an hibernation file")

    def _load_segments(self):
        base_layer = self.context.layers[self._base_layer]
        system_time = int.from_bytes(base_layer.read(0x020, 8), "little")
        systemTime = conversion.wintime_to_datetime(system_time)
        NumPagesForLoader = int.from_bytes(base_layer.read(0x058, 8), "little")
        FirstBootRestorePage = int.from_bytes(base_layer.read(0x068, 8), "little") 
        FirstKernelRestorePage = int.from_bytes(base_layer.read(0x070, 8), "little")
        KernelPagesProcessed = int.from_bytes(base_layer.read(0x230, 8), "little")

        # vollog.info(f"""
        #         SystemTime : {systemTime} \n
        #         NumPagesForLoader : {NumPagesForLoader} \n
        #         FirstBootRestorePage : {hex(FirstBootRestorePage)} \n
        #         KernelPageProcessed : {KernelPagesProcessed} \n
        #         FirstKernelRestorePage : {FirstKernelRestorePage} \n       
        # """)
        # TODO : If the FirstKernelRestorePage member of the header is non-zero, 
        # its value gives the page number of the start of the KernelRestore- Pages.
        # We need to check if this value is zero and not process the KernelRestorePages if so.

        offset = FirstBootRestorePage * self.PAGE_SIZE
        total_pages = NumPagesForLoader
        treated = 0

        while total_pages > treated:
            page_read, next_cs = self._read_compression_set(offset)
            offset += next_cs
            treated += page_read

        offset = FirstKernelRestorePage * self.PAGE_SIZE
        total_pages = KernelPagesProcessed
       
        treated = 0
        while total_pages > treated:
            page_read, next_cs = self._read_compression_set(offset)
            offset += next_cs
            treated += page_read        
        
        self._segments = sorted(self._segments, key=lambda x: x[0])

    def _read_compression_set(self, offset):
        """
            Desc : Read one compression set an extract the address of the compressed data
            Params : 
                - offset : the location of the compression set to read.
                - stream : the hibernation file stream.
            Return : The offset of the compressed data and the size.
        """
        base_layer = self.context.layers[self._base_layer]

        header = base_layer.read(offset, self.HEADER_SIZE)
        data = struct.unpack('<I', header)[0]
        number_of_descs = data & 0xff
        size_of_compressed_data = (data >> 8) & 0x3fffff
        huffman_compressed = (data >> 30) & 0x3
        mapped_address = offset+self.HEADER_SIZE+number_of_descs*self.PAGE_DESC_SIZE
        total_page_count = 0
        position = 0
        for i in range(number_of_descs):
            location = offset+self.HEADER_SIZE+i*self.PAGE_DESC_SIZE
            page_descriptor = base_layer.read(location, self.PAGE_DESC_SIZE)
            data = struct.unpack('<Q', page_descriptor)[0]
            Numpages = data & 0b1111  # get the lower 4 bits
            PageNum = data >> 4  # shift right 4 bits to get the upper 60 bits
            page_count = (1+ Numpages)
            total_page_count += page_count
            self._segments.append(
                (PageNum*self.PAGE_SIZE,
                 mapped_address,
                 self.PAGE_SIZE*page_count,
                 size_of_compressed_data
                )
            )
            for j in range(page_count):
                self._mapping[(PageNum+j)*self.PAGE_SIZE] = position*self.PAGE_SIZE
                position += 1

        total_page_size = total_page_count*self.PAGE_SIZE
        if total_page_size != size_of_compressed_data:
            self._compressed[mapped_address] = huffman_compressed
        return total_page_count, (4 + size_of_compressed_data + number_of_descs * self.PAGE_DESC_SIZE)  #Number of pages in the set, Size of the entire compression set


    def _decode_data(
        self, data: bytes, mapped_offset: int, offset: int, output_length: int
    ) -> bytes:
        start_offset, _, _, _ = self._find_segment(offset)
        if mapped_offset in self._compressed:
            decoded_data = uncompress(data, self._compressed[mapped_offset],65536)
        else:
            decoded_data = data
        page_offset = self._mapping[start_offset]
        decoded_data = decoded_data[page_offset + (offset - start_offset):]
        decoded_data = decoded_data[:output_length]
        return decoded_data


class HibernationFileStacker(interfaces.automagic.StackerLayerInterface):
    stack_order = 10
    @classmethod
    def stack(
        cls,
        context: interfaces.context.ContextInterface,
        layer_name: str,
        progress_callback: constants.ProgressCallback = None,
    ) -> Optional[interfaces.layers.DataLayerInterface]:
        try:
            HibernationLayer._check_header(context.layers[layer_name])
        except exceptions.LayerException:
            return None
        new_name = context.layers.free_layer_name("HibernationLayer")
        context.config[
            interfaces.configuration.path_join(new_name, "base_layer")
        ] = layer_name
        layer = HibernationLayer(context, new_name, new_name)
        cls.stacker_slow_warning()
        return layer