# This file is Copyright 2024 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
# References:
#   - https://www.forensicxlab.com/posts/hibernation/ : Vulgarized description of the hibernation file structure and the implementation of this layer.
#   - https://www.cct.lsu.edu/~golden/Papers/sylvehiber.pdf : Scientific paper.
#   - https://www.vergiliusproject.com/kernels/x64/ : Windows kernel structures used to track the evolution of the hibernation file structure in time.

from typing import Optional
import logging, struct
from volatility3.framework import interfaces, constants, exceptions
from volatility3.framework.layers import segmented
from volatility3.framework.layers.codecs import (
    lz77_plain_decompress,
    lz77_huffman_decompress,
)

vollog = logging.getLogger(__name__)


def uncompress(data: bytes, flag):
    """
    Desc:
    Params:
        - data: the compressed data from a compression set
        - flag: what is the decompression algorithm to use.
        - out_size: Size of the decompressed data
    Return: The decompressed data (consecutive pages).
    """
    if flag == 0 or flag == 1:
        return lz77_plain_decompress(data)  # See layers.codecs
    elif flag == 2 or flag == 3:
        return lz77_huffman_decompress(data, 65536)[0]  # See layers.codecs
    else:
        vollog.warning(
            f"A compression set could not be decompressed: Compression algorithm : {flag}"
        )
        raise ValueError("Cannot decompress the data.")


class HibernationLayer(segmented.NonLinearlySegmentedLayer):
    """
    A TranslationLayer that maps physical memory against a x64 Microsoft Windows hibernation file.
    This Translation Layer is meant to be used in conjunction with the Hibernation.Info and Hibernation.Dump plugins.
    """

    WINDOWS_10_2016_1703_TO_23H2 = 0
    WINDOW_8 = 1
    WINDOWS_10_2016_1507_1511 = 2
    WINDOWS_10_2016_1607 = 3

    # TODO: Make me compatible with x86 by adding options to the Hib plugins.
    PAGE_SIZE = 4096  # x64 page size.
    HEADER_SIZE = 4
    PAGE_DESC_SIZE = 8

    def __init__(
        self,
        context: interfaces.context.ContextInterface,
        config_path: str,
        name: str,
        **kwargs,
    ):
        """
        Initializes the Hibernation file layer.
        """
        self._compressed = (
            {}
        )  # Keep track of which compression algorithm by each mapped compressed data.
        self._mapping = (
            {}
        )  # This will hold the mapping between the PageNumber in the decompressed data vs the physical page number.

        if "plugins.Dump.version" in context.config:
            # The user is using the hibernation.Dump plugin, so the version must be known.
            # See possible version in the table below.
            self.version = context.config["plugins.Dump.version"]
        else:
            self.version = -1

        self.NPFL_OFFSET = 0x058  # (NumPagesForLoader)
        self.FBRP_OFFSET = 0x068  # (FirstBootRestorePage)

        """
        Mapping for each 'group' of Windows version sharing the same offsets
        ---------------------------------------------------------------------------------------------------------
        | Windows Versions                          | FirstKernelRestorePage (FKRP) | KernelPagesProcessed (KPP)|   
        | ------------------------------------------|:-----------------------------:|:-------------------------:|
        | Windows 8/8.1                             |               0x68            |	        0x1C8           | 
        | Windows 10 2016 1507-1511                 |               0x70            |	        0x218           | 
        | Windows 10 2016 1607                      |               0x70            |	        0x220           |
        | Windows 10 2016 1703 - Windows 11 23H2    |               0x70            |	        0x230           |
        ---------------------------------------------------------------------------------------------------------
        """
        if self.version == self.WINDOWS_10_2016_1703_TO_23H2:
            self.FKRP_OFFSET = 0x070
            self.KPP_OFFSET = 0x230
        elif self.version == self.WINDOW_8:
            self.FKRP_OFFSET = 0x68
            self.KPP_OFFSET = 0x1C8
        elif self.version == self.WINDOWS_10_2016_1507_1511:
            self.FKRP_OFFSET = 0x70
            self.KPP_OFFSET = 0x218
        elif self.version == self.WINDOWS_10_2016_1607:
            self.FKRP_OFFSET = 0x70
            self.KPP_OFFSET = 0x220
        else:
            raise exceptions.LayerException(name, "The version provided is not valid")
        super().__init__(context, config_path, name, **kwargs)

    @classmethod
    def _check_header(
        cls, base_layer: interfaces.layers.DataLayerInterface, name: str = ""
    ):
        header = base_layer.read(0, 4)
        if header != b"HIBR":
            raise exceptions.LayerException(name, "No Hibernation magic bytes")
        else:
            vollog.info("Detecting an hibernation file")

    def _load_segments(self):
        """
        Loading segments is a 2 STEP operation:
            - Step 1: extracting the pages from the BootSection if any.
            - Step 2: extracting the pages from the KernelSection if any.
        """
        base_layer = self.context.layers[self._base_layer]
        NumPagesForLoader = int.from_bytes(
            base_layer.read(self.NPFL_OFFSET, 8), "little"
        )
        FirstBootRestorePage = int.from_bytes(
            base_layer.read(self.FBRP_OFFSET, 8), "little"
        )

        offset = FirstBootRestorePage * self.PAGE_SIZE
        total_pages = NumPagesForLoader
        treated = 0

        while total_pages > treated:
            page_read, next_compression_set = self._read_compression_set(offset)
            offset += next_compression_set
            treated += page_read

        if "plugins.Dump.version" in self.context.config:
            # The user is using the hibernation.Dump plugin so we can parse the KernelSection
            FirstKernelRestorePage = int.from_bytes(
                base_layer.read(self.FKRP_OFFSET, 8), "little"
            )
            KernelPagesProcessed = int.from_bytes(
                base_layer.read(self.KPP_OFFSET, 8), "little"
            )
            offset = FirstKernelRestorePage * self.PAGE_SIZE
            total_pages = KernelPagesProcessed

            treated = 0
            while total_pages > treated:
                page_read, next_compression_set = self._read_compression_set(offset)
                offset += next_compression_set
                treated += page_read
        self._segments = sorted(self._segments, key=lambda x: x[0])

    def _read_compression_set(self, offset):
        """
        Desc: Read one compression set an extract the address of the compressed data
        Params:
            - offset : the location of the compression set to read.
            - stream : the hibernation file stream.
        Return: The offset of the compressed data and the size.
        """

        base_layer = self.context.layers[self._base_layer]
        header = base_layer.read(offset, self.HEADER_SIZE)
        data = struct.unpack("<I", header)[0]  # Compression set header extraction.
        number_of_descs = data & 0xFF  # First 8 least significant bits.
        if number_of_descs == 0 or number_of_descs > 16:
            # See references
            raise exceptions.LayerException(
                self.name, "The hibernation file is corrupted."
            )

        size_of_compressed_data = (
            data >> 8
        ) & 0x3FFFFF  # Next 22 least significant bytes.
        huffman_compressed = (data >> 30) & 0x3  # Most significant bit.

        # Now we know where is the start of the page descriptors in the hibernation file.
        mapped_address = (
            offset + self.HEADER_SIZE + number_of_descs * self.PAGE_DESC_SIZE
        )
        total_page_count = 0
        position = 0
        for i in range(number_of_descs):
            # Go fetch and parse each page descriptor.
            location = offset + self.HEADER_SIZE + i * self.PAGE_DESC_SIZE
            page_descriptor = base_layer.read(location, self.PAGE_DESC_SIZE)
            data = struct.unpack("<Q", page_descriptor)[0]
            Numpages = data & 0b1111  # Get the lower 4 bits
            PageNum = data >> 4  # Shift right 4 bits to get the upper 60 bits
            page_count = 1 + Numpages
            total_page_count += page_count
            self._segments.append(
                (
                    PageNum * self.PAGE_SIZE,
                    mapped_address,
                    self.PAGE_SIZE * page_count,
                    size_of_compressed_data,
                )
            )
            for j in range(page_count):
                # Track the physical page number vs the page number in the compression set
                self._mapping[(PageNum + j) * self.PAGE_SIZE] = (
                    position * self.PAGE_SIZE
                )
                position += 1

        total_page_size = total_page_count * self.PAGE_SIZE

        if total_page_size != size_of_compressed_data:
            # This means compression so we track wich compression sets we actually need to decompress
            self._compressed[mapped_address] = huffman_compressed
        return total_page_count, (
            4 + size_of_compressed_data + number_of_descs * self.PAGE_DESC_SIZE
        )  # Number of pages in the set, Size of the entire compression set

    def _decode_data(
        self, data: bytes, mapped_offset: int, offset: int, output_length: int
    ) -> bytes:
        """
        Desc: decode the compressed data of one compression set
        Params:
            - data : the compressed data
            - mapped_offset : starting location of the compressed data in the hib file
            - offset: The offset inside the resulting raw file
            - output_length: what is the size of the expected decompressed pages
        Return: The decompressed data
        """
        start_offset, _mapped_offset, _size, _mapped_size = self._find_segment(offset)
        if mapped_offset in self._compressed:
            decoded_data = uncompress(data=data, flag=self._compressed[mapped_offset])
        else:
            # The data is not in our mapping so it's uncompressed.
            decoded_data = data
        page_offset = self._mapping[start_offset]
        decoded_data = decoded_data[page_offset + (offset - start_offset) :]
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
        context.config[interfaces.configuration.path_join(new_name, "base_layer")] = (
            layer_name
        )
        layer = HibernationLayer(context, new_name, new_name)
        cls.stacker_slow_warning()
        return layer
