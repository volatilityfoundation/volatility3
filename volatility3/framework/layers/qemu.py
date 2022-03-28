# This file is Copyright 2020 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
import functools
import json
import logging
import re
import struct
from typing import Optional, Dict, Any, Tuple, List, Set

from volatility3.framework import interfaces, exceptions, constants
from volatility3.framework.layers import segmented, scanners
from volatility3.framework.symbols import intermed

vollog = logging.getLogger(__name__)

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
        self._architecture = None
        self._PCI_hole = None
        self._compressed: Set[int] = set()
        self._current_segment_name = b''
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
        chunk_size = 4096
        data = b''
        for i in range(base_layer.maximum_address, base_layer.minimum_address, -chunk_size):
            if i != base_layer.maximum_address:
                data = (base_layer.read(i, chunk_size) + data).rstrip(b'\x00')
                if b'\x00' in data:
                    last_null_byte = data.rfind(b'\x00')
                    start_of_json = data.find(b'{', last_null_byte)
                    if start_of_json >= 0:
                        data = data[start_of_json:]
                        return json.loads(data)
                    # No JSON configuration found at the end of the file, return empty dict
                    return dict()
        raise exceptions.LayerException(name, "Invalid JSON configuration at the end of the file")

    @staticmethod
    def _get_pci_hole(architecture: Optional[Tuple[str, Optional[str]]], ram_size: int) -> \
            Optional[Tuple[int, int]]:
        """Returns the location and size of the PCI-hole for the given architecture and RAM size.

        Args:
            architecture: (Optionally) A tuple of strings containing the name (in lowercase) and (optionally) the
                version of the used QEMU target architecture
            ram_size: Size of the RAM in bytes

        Returns:
            (Optionally) A tuple containing the start and size of the PCI hole
        """

        # See https://qemu.readthedocs.io/en/latest/devel/memory.html for more info
        #
        # At least the following values could occur for devices using > 3-4 GB RAM:
        # +--------------------------------+--------------------------------+------------+-------------+
        # | Architecture                   | Reference Code                 | Hole Start | Hole End    |
        # +--------------------------------+--------------------------------+------------+-------------+
        # | PC i440FX + PIIX "New Default" | qemu/hw/i386/pc_piix.c:98      | 0xc0000000 | 0x100000000 |
        # | PC i440FX + PIIX "Old Default" | qemu/hw/i386/pc_piix.c:98      | 0xe0000000 | 0x100000000 |
        # | PC Q35 + ICH9                  | qemu/hw/i386/pc_q35.c:141      | 0x80000000 | 0x100000000 |
        # | MicroVM                        | qemu/hw/i386/microvm.c:291     | 0xc0000000 | 0x100000000 |
        # | Xen                            | qemu/hw/i386/xen/xen-hvm.c:248 | 0xf0000000 | 0x100000000 |
        # +--------------------------------+--------------------------------+------------+-------------+
        #
        # MicroVM and Xen haven't been implemented yet
        #
        # For now, we assume that the parameter max-ram-below-4g is not set, since this parameter influences the size
        # and location of the memory gap. Deviating hole sizes could eventually be detected for Linux by e.g. scanning
        # for dmesg entries with a regex like rb'\[mem (0x[0-9a-f]{4,10})-0x[0-9a-f]{4,10}\] available for PCI devices'

        end = 0x100000000

        if architecture:
            if architecture[0] == 'i440fx':
                if ram_size >= 0xe0000000:
                    if architecture[1] and architecture[1] < '2.0':
                        start = 0xe0000000
                    else:
                        start = 0xc0000000
                else:
                    vollog.log(constants.LOGLEVEL_VV, f"No PCI-hole present in this memory layout "
                                                      f"(PC i440FX + RAM size < 0xe0000000)")
                    return None

            elif architecture[0] == 'q35':
                if ram_size >= 0xb0000000:
                    start = 0x80000000
                else:
                    vollog.log(constants.LOGLEVEL_VV, f"No PCI-hole present in this memory layout "
                                                      f"(Q35 + RAM size < 0xb0000000)")
                    return None
            else:
                vollog.warning(f"Default location of PCI-hole not known for target architecture {architecture[0]}")
                return None

            vollog.log(constants.LOGLEVEL_VV, f"PCI-hole for detected target architecture is usually located at "
                                              f"0x{start:x}, using this location")
            return start, end - start
        else:
            vollog.warning("Could not determine target architecture, the possible presence of a PCI-hole is not taken "
                           "into account")
            return None

    def _determine_architecture(self, base_layer: interfaces.layers.DataLayerInterface) -> \
            Optional[Tuple[str, Optional[str]]]:
        """Tries to determine the QEMU target architecture being used

        Args:
            base_layer: Layer to operate on

        Returns:
            (Optionally) A tuple of strings containing the name (in lowercase) and (optionally) the version of the used
                QEMU target architecture
        """
        # MicroVM and Xen haven't been implemented yet

        # First try to find a string containing both architecture and version
        architecture_pattern = rb'pc-(i440fx|q35)-([0-9]{1,2}.[0-9]{1,2}(?:.[0-9]{1,2})?)'
        res = scanners.RegExScanner(architecture_pattern)
        for offset in base_layer.scan(context = self.context, scanner = res):
            line = base_layer.read(offset, 64)
            regex_results = re.search(architecture_pattern, line)
            architecture = regex_results.groups()[0].decode()
            version = regex_results.groups()[1].decode()
            vollog.log(constants.LOGLEVEL_VV, f"Detected QEMU target architecture to be {architecture}-{version}")
            return architecture, version

        # If that does not work, look in configuration JSON for devices specific to a certain architecture
        architecture = None
        for device in self._configuration.get('devices', []):
            device_name = device.get('vmsd_name', '').lower()
            if 'i440fx' in device_name or 'piix' in device_name:
                architecture = 'i440fx'
                break
            elif 'ich9' in device_name:
                architecture = 'q35'
                break
        if architecture:
            vollog.log(constants.LOGLEVEL_VV, f"Detected QEMU target architecture to be {architecture}")
            return architecture, None

        # Still haven't found architecture, switch to fallback-method
        architecture_pattern = rb'Standard PC \((i440FX|Q35)'
        res = scanners.RegExScanner(architecture_pattern)
        for offset in base_layer.scan(context = self.context, scanner = res):
            line = base_layer.read(offset, 64)
            regex_results = re.search(architecture_pattern, line)
            architecture = regex_results.groups()[0].decode().lower()
            vollog.log(constants.LOGLEVEL_VV, f"Detected QEMU target architecture to be {architecture}")
            return architecture, None

        vollog.warning("Could not determine QEMU target architecture!")
        return None

    def _get_ram_segments(self, index: int, page_size: int) -> Tuple[List[Tuple[int, int, int, int]], int]:
        """Recovers the new index and any sections of memory from a ram section"""
        done = None
        segments = []

        base_layer = self.context.layers[self._base_layer]

        while not done:
            # Use struct.unpack here for performance improvements
            addr = struct.unpack('>Q', base_layer.read(index, 8))[0]
            # Flags are stored in the n least significant bits, where n equals the bit-length of pagesize
            flags = addr & (page_size - 1)
            # addr equals the highest multiple of pagesize <= offset
            # (We assume that page_size is a power of 2)
            addr = addr ^ (addr & (page_size - 1))
            index += 8

            # Skip PCI-hole
            if self._PCI_hole and addr >= self._PCI_hole[0]:
                addr += self._PCI_hole[1]

            if flags & self.SEGMENT_FLAG_MEM_SIZE:
                namelen = self._context.object(self._qemu_table_name + constants.BANG + 'unsigned char',
                                               offset = index,
                                               layer_name = self._base_layer)
                while namelen != 0:
                    name = base_layer.read(index + 1, namelen)
                    total_size = self._context.object(self._qemu_table_name + constants.BANG + 'unsigned long long',
                                                      offset = index + 1 + namelen,
                                                      layer_name = self._base_layer)
                    if name == b'pc.ram':
                        self._PCI_hole = self._get_pci_hole(architecture = self._architecture, ram_size = total_size)
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
        if not self._architecture:
            self._architecture = self._determine_architecture(base_layer)
        section_byte = -1
        index = 8
        section_info = dict()
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
                # instance_id = self.context.object(self._qemu_table_name + constants.BANG + 'unsigned long',
                #                                    offset = index,
                #                                    layer_name = self._base_layer)
                index += 4
                version_id = self.context.object(self._qemu_table_name + constants.BANG + 'unsigned long',
                                                 offset = index,
                                                 layer_name = self._base_layer)
                index += 4
                # Store section info for handling QEVM_SECTION_PARTs later on
                section_info[current_section_id] = {'name': name, 'version_id': version_id}
                # Read additional data
                index = self.extract_data(index, name, version_id)
            elif section_byte == self.QEVM_SECTION_PART or section_byte == self.QEVM_SECTION_END:
                section_id = self.context.object(self._qemu_table_name + constants.BANG + 'unsigned long',
                                                 offset = index,
                                                 layer_name = self._base_layer)
                current_section_id = section_id
                index += 4
                # Read additional data
                index = self.extract_data(index, section_info[current_section_id]['name'],
                                          section_info[current_section_id]['version_id'])
            elif section_byte == self.QEVM_SECTION_FOOTER:
                section_id = self.context.object(self._qemu_table_name + constants.BANG + 'unsigned long',
                                                 offset = index,
                                                 layer_name = self._base_layer)
                index += 4
                if section_id != current_section_id:
                    raise exceptions.LayerException(
                        self._name, f'QEMU section footer mismatch: {current_section_id} and {section_id}')
            elif section_byte == self.QEVM_EOF:
                pass
            else:
                raise exceptions.LayerException(self._name, f'QEMU unknown section encountered: {section_byte}')

    def extract_data(self, index, name, version_id):
        if name == 'ram':
            if version_id != 4:
                raise exceptions.LayerException(f"QEMU unknown RAM version_id {version_id}")
            new_segments, index = self._get_ram_segments(index, self._configuration.get('page_size', 4096))
            self._segments += new_segments
        elif name == 'spapr/htab':
            if version_id != 1:
                raise exceptions.LayerException(f"QEMU unknown HTAB version_id {version_id}")
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
        elif name == 'dirty-bitmap':
            index += 1
        elif name == 'pbs-state':
            section_len = self.context.object(self._qemu_table_name + constants.BANG + 'unsigned long long',
                                              offset = index,
                                              layer_name = self._base_layer)
            index += 8 + section_len
        return index

    def _decode_data(self, data: bytes, mapped_offset: int, offset: int, output_length: int) -> bytes:
        """Takes the full segment from the base_layer that the data occurs in, checks whether it's compressed
        (by locating it in the segment list and verifying if that address is compressed), then reading/expanding the
        data, and finally cutting it to the right size.  Offset may be the address requested rather than the location
        of the starting data.  It is the responsibility of the layer to turn the provided data chunk into the right
        portion of data necessary.
        """
        page_size = self._configuration.get('page_size', 4096)
        # start_offset equals the highest multiple of pagesize <= offset
        # (We assume that page_size is a power of 2)
        start_offset = offset ^ (offset & (page_size - 1))
        if start_offset in self._compressed:
            data = (data * page_size)
        result = data[offset - start_offset:output_length + offset - start_offset]
        return result

    @functools.lru_cache(maxsize = 512)
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
