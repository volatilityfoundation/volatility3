# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
from typing import Optional
import logging, struct
from volatility3.framework import interfaces, constants, exceptions
from volatility3.framework.layers import segmented
from volatility3.framework.renderers import conversion
from volatility3.framework.layers.codecs import lz77_plain_decompress, lz77_huffman_decompress


vollog = logging.getLogger(__name__)


def uncompress(data: bytes, huffman, out_size):
    if huffman == 0 or huffman == 1:
        return lz77_plain_decompress(data)
    elif huffman == 2 or huffman == 3:
        return lz77_huffman_decompress(data,out_size)[0]
    else: 
        vollog.warning(f"A compression set could not be decompressed : Compression algorithm : {huffman}")
        raise ValueError('Cannot decompress the data.')


class HibernationFileException(exceptions.LayerException):
    """Thrown when an error occurs with the underlying Hibernation file format."""

class HibernationLayer(segmented.NonLinearlySegmentedLayer):
    """
    A TranslationLayer that maps physical memory against a Microsoft Windows hibernation file (x64 only for now).
    """
    PAGE_SIZE = 4096 #For x64 by default
    HEADER_SIZE = 4
    PAGE_DESC_SIZE = 8
    def __init__(self, context: interfaces.context.ContextInterface, config_path: str, name: str, **kwargs):
        """
        Initializes the Hibernation file layer.
        """
        # Call the superclass constructor.
        self._compressed = {}
        self._mapping = {}
        self.version = 0 #By default we want to analyze modern windows hiberfiles (Windows 10 2016 1703 to Windows 11 23H2)
        if "plugins.Dump.version" in context.config:
            # The user is using the hibernation.Dump plugin
            self.version = context.config["plugins.Dump.version"]
        self.NPFL_OFFSET = 0x058
        self.FBRP_OFFSET = 0x068

        """
            | Windows Versions                          | FirstKernelRestorePage | KernelPagesProcessed   |   
            | ------------------------------------------|:----------------------:|:----------------------:|
            | Windows 8/8.1                             |           0x68         |	    0x1C8             | 
            | Windows 10 2016 1507-1511                 |           0x70         |	    0x218             | 
            | Windows 10 2016 1607                      |           0x70         |	    0x220             |
            | Windows 10 2016 1703 - Windows 11 23H2    |           0x70         |	    0x230             |
        """
        if self.version == 0:
            self.FKRP_OFFSET = 0x070
            self.KPP_OFFSET = 0x230
        if self.version == 1:
            self.FKRP_OFFSET = 0x68
            self.KPP_OFFSET = 0x1C8
        if self.version == 2:
            self.FKRP_OFFSET = 0x70
            self.KPP_OFFSET = 0x218
        if self.version == 3:
            self.FKRP_OFFSET = 0x70
            self.KPP_OFFSET = 0x220

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
        NumPagesForLoader = int.from_bytes(base_layer.read(self.NPFL_OFFSET, 8), "little")
        FirstBootRestorePage = int.from_bytes(base_layer.read(self.FBRP_OFFSET, 8), "little") 
        FirstKernelRestorePage = int.from_bytes(base_layer.read(self.FKRP_OFFSET, 8), "little")
        KernelPagesProcessed = int.from_bytes(base_layer.read(self.KPP_OFFSET, 8), "little")
        
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