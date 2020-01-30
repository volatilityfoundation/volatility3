import json
import math
from typing import Optional, Dict, Any, Tuple, List

from volatility.framework import interfaces, exceptions, constants
from volatility.framework.layers import segmented
from volatility.framework.symbols import intermed


class QemuSuspendLayer(segmented.NonLinearlySegmentedLayer):
    """A Qemu suspend-to-disk translation layer."""

    QEVM_EOF = 0x00
    QEVM_SECTION_START = 0x01
    QEVM_SECTION_PART = 0x02
    QEVM_SECTION_END = 0x03
    QEVM_SECTION_FULL = 0x04
    QEVM_SUBSECTION = 0x05
    QEVM_VMDESCRIPTION = 0x06
    QEVM_CONFIGURATION = 0x07
    QEVM_SECTION_FOOTER = 0x7e
    HASH_PTE_SIZE_64 = 16

    SEGMENT_FLAG_COMPRESS = 0x02
    SEGMENT_FLAG_MEM_SIZE = 0x04
    SEGMENT_FLAG_PAGE = 0x08
    SEGMENT_FLAG_EOS = 0x10
    SEGMENT_FLAG_CONTINUE = 0x20
    SEGMENT_FLAG_XBZRLE = 0x40
    SEGMENT_FLAG_HOOK = 0x80

    def __init__(self,
                 context: interfaces.context.ContextInterface,
                 config_path: str,
                 name: str,
                 metadata: Optional[Dict[str, Any]] = None) -> None:
        self._qemu_table_name = intermed.IntermediateSymbolTable.create(context, config_path, 'generic', 'qemu')
        self._configuration = None
        self._compressed = set()
        self._current_segment_name = ''
        super().__init__(context = context, config_path = config_path, name = name, metadata = metadata)

    @classmethod
    def _check_header(cls, base_layer: interfaces.layers.DataLayerInterface, name: str = ''):
        header = base_layer.read(0, 8)
        if header[:4] != b'\x51\x45\x56\x4D':
            raise exceptions.LayerException(name, 'No QEMU magic bytes')
        if header[4:] != b'\x00\x00\x00\x03':
            raise exceptions.LayerException(name, 'Unsupported QEMU version found')

    def _read_configuration(self, base_layer: interfaces.layers.DataLayerInterface, name: str) -> Any:
        """Reads the JSON configuration from the end of the file"""
        chunk_size = 0x4096
        data = b''
        for i in range(base_layer.maximum_address, base_layer.minimum_address, -chunk_size):
            if i != base_layer.maximum_address:
                data = base_layer.read(i, chunk_size) + data
                if b'\x00' in data:
                    start = data.rfind(b'\x00')
                    data = data[data.find(b'{', start):]
                    return json.loads(data)
        raise exceptions.LayerException(name, "Could not load JSON configuration from the end of the file")

    def _get_ram_segments(self, index: int, page_size: int) -> Tuple[List[Tuple[int, int, int, int]], int]:
        """Recovers the new index and any sections of memory from a ram section"""
        done = None
        segments = []

        base_layer = self.context.layers[self._base_layer]

        while not done:
            addr = self.context.object(self._qemu_table_name + constants.BANG + 'unsigned long long',
                                       offset = index,
                                       layer_name = self._base_layer)
            flags = addr & (page_size - 1)
            page_size_bits = int(math.log(page_size, 2))
            addr = (addr >> page_size_bits) << page_size_bits
            index += 8

            if flags & self.SEGMENT_FLAG_MEM_SIZE:
                namelen = self._context.object(self._qemu_table_name + constants.BANG + 'unsigned char',
                                               offset = index,
                                               layer_name = self._base_layer)
                while namelen != 0:
                    # if base_layer.read(index + 1, namelen) == b'pc.ram':
                    #     total_size = self._context.object(self._qemu_table_name + constants.BANG + 'unsigned long long',
                    #                                       offset = index + 1 + namelen,
                    #                                       layer_name = self._base_layer)
                    index += 1 + namelen + 8
                    namelen = self._context.object(self._qemu_table_name + constants.BANG + 'unsigned char',
                                                   offset = index,
                                                   layer_name = self._base_layer)
            if flags & (self.SEGMENT_FLAG_COMPRESS | self.SEGMENT_FLAG_PAGE):
                if not (flags & self.SEGMENT_FLAG_CONTINUE):
                    namelen = self._context.object(self._qemu_table_name + constants.BANG + 'unsigned char',
                                                   offset = index,
                                                   layer_name = self._base_layer)
                    self._current_segment_name = base_layer.read(index + 1, namelen)
                    index += 1 + namelen
                if flags & self.SEGMENT_FLAG_COMPRESS:
                    if self._current_segment_name == b'pc.ram':
                        segments.append((addr, index, page_size, 1))
                        self._compressed.add(addr)
                    index += 1
                else:
                    if self._current_segment_name == b'pc.ram':
                        segments.append((addr, index, page_size, page_size))
                    index += page_size
            if flags & self.SEGMENT_FLAG_XBZRLE:
                raise exceptions.LayerException(self.name, "XBZRLE compression not supported")
            if flags & self.SEGMENT_FLAG_EOS:
                done = True
        return segments, index

    def _load_segments(self):
        base_layer = self.context.layers[self._base_layer]
        self._check_header(base_layer, self.name)
        if not self._configuration:
            self._configuration = self._read_configuration(base_layer, self.name)
        section_byte = -1
        index = 8
        current_section_id = -1
        version_id = -1
        name = None
        while section_byte != self.QEVM_EOF and index <= base_layer.maximum_address:
            section_byte = self.context.object(self._qemu_table_name + constants.BANG + 'unsigned char',
                                               offset = index,
                                               layer_name = self._base_layer)
            index += 1
            if section_byte == self.QEVM_CONFIGURATION:
                section_len = self.context.object(self._qemu_table_name + constants.BANG + 'unsigned long',
                                                  offset = index,
                                                  layer_name = self._base_layer)
                index += 4 + section_len
            elif section_byte == self.QEVM_SECTION_START or section_byte == self.QEVM_SECTION_FULL:
                section_id = self.context.object(self._qemu_table_name + constants.BANG + 'unsigned long',
                                                 offset = index,
                                                 layer_name = self._base_layer)
                current_section_id = section_id
                index += 4
                name_len = self.context.object(self._qemu_table_name + constants.BANG + 'unsigned char',
                                               offset = index,
                                               layer_name = self._base_layer)
                index += 1
                name = self.context.object(self._qemu_table_name + constants.BANG + 'string',
                                           offset = index,
                                           layer_name = self._base_layer,
                                           max_length = name_len)
                index += name_len
                instance_id = self.context.object(self._qemu_table_name + constants.BANG + 'unsigned long',
                                                  offset = index,
                                                  layer_name = self._base_layer)
                index += 4
                version_id = self.context.object(self._qemu_table_name + constants.BANG + 'unsigned long',
                                                 offset = index,
                                                 layer_name = self._base_layer)
                index += 4
                # Read additional data
                index = self.extract_data(index, name, version_id)
            elif section_byte == self.QEVM_SECTION_PART or section_byte == self.QEVM_SECTION_END:
                section_id = self.context.object(self._qemu_table_name + constants.BANG + 'unsigned long',
                                                 offset = index,
                                                 layer_name = self._base_layer)
                current_section_id = section_id
                index += 4
                # Read additional data
                index = self.extract_data(index, name, version_id)
            elif section_byte == self.QEVM_SECTION_FOOTER:
                section_id = self.context.object(self._qemu_table_name + constants.BANG + 'unsigned long',
                                                 offset = index,
                                                 layer_name = self._base_layer)
                index += 4
                if section_id != current_section_id:
                    raise exceptions.LayerException(
                        self._name, 'QEMU section footer mismatch: {} and {}'.format(current_section_id, section_id))
            elif section_byte == self.QEVM_EOF:
                pass
            else:
                raise exceptions.LayerException(self._name, 'QEMU unknown section encountered: {}'.format(section_byte))

    def extract_data(self, index, name, version_id):
        if name == 'ram':
            if version_id != 4:
                raise exceptions.LayerException("QEMU unknown RAM version_id {}".format(version_id))
            new_segments, index = self._get_ram_segments(index, self._configuration.get('page_size', None) or 4096)
            self._segments += new_segments
        elif name == 'spapr/htab':
            if version_id != 1:
                raise exceptions.LayerException("QEMU unknown HTAB version_id {}".format(version_id))
            header = self.context.object(self._qemu_table_name + constants.BANG + 'unsigned long',
                                         offset = index,
                                         layer_name = self._base_layer)
            index += 4
            if header == 0:
                htab_index = -1
                htab_n_valid = 0
                htab_n_invalid = 0
                while htab_index != 0 and htab_n_valid != 0 and htab_n_invalid != 0:
                    htab = self.context.object(self._qemu_table_name + constants.BANG + 'htab',
                                               offset = index,
                                               layer_name = self._base_layer)
                    htab_index, htab_n_valid, htab_n_invalid = htab
                    index += 8 + (htab_n_valid * self.HASH_PTE_SIZE_64)
        return index

    def _decode_data(self, data: bytes, mapped_offset: int, offset: int, output_length: int) -> bytes:
        if mapped_offset in self._compressed:
            return (data * 0x1000)[:output_length]
        return data

    def read(self, offset: int, length: int, pad: bool = False) -> bytes:
        return super().read(offset, length, pad)


class QemuStacker(interfaces.automagic.StackerLayerInterface):
    stack_order = 10

    @classmethod
    def stack(cls,
              context: interfaces.context.ContextInterface,
              layer_name: str,
              progress_callback: constants.ProgressCallback = None) -> Optional[interfaces.layers.DataLayerInterface]:
        try:
            QemuSuspendLayer._check_header(context.layers[layer_name])
        except exceptions.LayerException:
            return None
        new_name = context.layers.free_layer_name("QemuSuspendLayer")
        context.config[interfaces.configuration.path_join(new_name, "base_layer")] = layer_name
        layer = QemuSuspendLayer(context, new_name, new_name)
        cls.stacker_slow_warning()
        return layer
