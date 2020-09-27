import logging
import math
from typing import Optional, Dict, Any, List, Iterable, Tuple

from volatility import classproperty
from volatility.framework import interfaces, exceptions
from volatility.framework.configuration import requirements
from volatility.framework.layers import linear

vollog = logging.getLogger(__name__)


class Arm64Exception(exceptions.LayerException):
    pass


class AArch64(linear.LinearlyMappedLayer):
    _page_size_in_bits = 12  # Minimum page size, for skipping invlad addresses
    _bits_per_register = 64
    _maxphyaddr = 48
    _maxvirtaddr = _maxphyaddr

    # Lists the page levels based on granule size
    structures = {
        0x0: [(47, 39),
              (38, 30),
              (29, 21),
              (20, 12)],
        0x1: [(47, 47),
              (46, 36),
              (35, 25),
              (24, 14)],
        0x3: [(47, 42),
              (41, 29),
              (28, 16)]
    }

    def __init__(self,
                 context: interfaces.context.ContextInterface,
                 config_path: str,
                 name: str,
                 metadata: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(context = context, config_path = config_path, name = name, metadata = metadata)
        self._base_layer = self.config["memory_layer"]
        self._swap_layers = []  # type: List[str]
        self._translation_control_register = self.config["translation_control_register"]

        self._translation_table_base = [self.config["translation_table_base0"],
                                        self.config["translation_table_base1"]]
        try:
            self._structure_index = [self.structures[self._mask(self._translation_control_register, 15, 14)],
                                     self.structures[self._mask(self._translation_control_register, 31, 30)]]
        except IndexError:
            raise Arm64Exception("Invalid translation control register")
        self._most_significant_bits = [self._mask(self._translation_control_register, 5, 0),
                                       self._mask(self._translation_control_register, 21, 16)]

    @staticmethod
    def _mask(value: int, high_bit: int, low_bit: int, shift: int = 0) -> int:
        """Returns the bits of a value between highbit and lowbit inclusive."""
        high_mask = (1 << (high_bit + 1)) - 1
        low_mask = (1 << low_bit) - 1
        mask = (high_mask ^ low_mask)
        return (value & mask) >> (low_bit - 1)

    def _translate(self, offset: int) -> Tuple[int, int, str]:
        """Translates a virtual offset to a physical one within this segment

        Returns the translated address, and the maximum offset within the block
        """
        selector = self._mask(offset, 55, 55)

        # Test for sign extension
        if self._most_significant_bits[selector] < 8:
            val = self._mask(offset, 8 - self._most_significant_bits[selector] + 55, 55)
            if math.log(val + 1, 2) != 8 - self._most_significant_bits[selector]:
                raise Arm64Exception("Bits not correctly sign extended")

        structure = self._structure_index[selector]
        entry_bits = (self._structure_index[selector][0][0], self._structure_index[selector][-1][1])
        table_offset = self._translation_table_base[selector]
        base_layer = self.context.layers[self._base_layer]
        register_size = self._bits_per_register // 8
        low_bit = 0
        level = 0
        for (high_bit, low_bit) in structure:
            index = self._mask(offset, high_bit, low_bit)
            entry = int.from_bytes(base_layer.read(table_offset + (index + register_size), register_size),
                                   byteorder = 'big')
            if not (entry & 0x1):
                raise exceptions.PagedInvalidAddressException(layer_name = self.name,
                                                              invalid_address = offset,
                                                              invalid_bits = high_bit,
                                                              entry = entry)
            table_descriptor = self._mask(entry, 1, 0)
            table_offset = self._mask(entry, entry_bits[0], entry_bits[1]) << (entry_bits[1] - 1)

            # If we're a block, then stop going round
            if not bool(table_descriptor):
                break
            level += 1

        if low_bit == 0:
            raise Arm64Exception("No structure found")
        physical_offset = table_offset + self._mask(offset, low_bit - 1, 0)

        return physical_offset, physical_offset & ((1 << low_bit) - 1), self._base_layer

    def is_valid(self, offset: int, length: int = 1) -> bool:
        """Returns whether the address offset can be translated to a valid
        address."""
        try:
            # TODO: Consider reimplementing this, since calls to mapping can call is_valid
            return all([
                self._context.layers[layer].is_valid(mapped_offset)
                for _, _, mapped_offset, _, layer in self.mapping(offset, length)
            ])
        except exceptions.InvalidAddressException:
            return False

    def mapping(self,
                offset: int,
                length: int,
                ignore_errors: bool = False) -> Iterable[Tuple[int, int, int, int, str]]:
        """Returns a sorted iterable of (offset, sublength, mapped_offset, mapped_length, layer)
        mappings.

        This allows translation layers to provide maps of contiguous
        regions in one layer
        """
        if length == 0:
            try:
                mapped_offset, _, layer_name = self._translate(offset)
                if not self._context.layers[layer_name].is_valid(mapped_offset):
                    raise exceptions.InvalidAddressException(layer_name = layer_name, invalid_address = mapped_offset)
            except exceptions.InvalidAddressException:
                if not ignore_errors:
                    raise
                return
            yield offset, length, mapped_offset, length, layer_name
            return
        while length > 0:
            try:
                chunk_offset, page_size, layer_name = self._translate(offset)
                chunk_size = min(page_size - (chunk_offset % page_size), length)
                if not self._context.layers[layer_name].is_valid(chunk_offset, chunk_size):
                    raise exceptions.InvalidAddressException(layer_name = layer_name, invalid_address = chunk_offset)
            except (exceptions.PagedInvalidAddressException, exceptions.InvalidAddressException) as excp:
                if not ignore_errors:
                    raise
                # We can jump more if we know where the page fault failed
                if isinstance(excp, exceptions.PagedInvalidAddressException):
                    mask = (1 << excp.invalid_bits) - 1
                else:
                    mask = (1 << self._page_size_in_bits) - 1
                length_diff = (mask + 1 - (offset & mask))
                length -= length_diff
                offset += length_diff
            else:
                yield offset, chunk_size, chunk_offset, chunk_size, layer_name
                length -= chunk_size
                offset += chunk_size

    @property
    def dependencies(self) -> List[str]:
        """Returns a list of the lower layer names that this layer is dependent
        upon."""
        return [self._base_layer]

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.TranslationLayerRequirement(name = 'memory_layer', optional = False),
            requirements.IntRequirement(name = 'translation_table_base0', optional = False),
            requirements.IntRequirement(name = 'translation_table_base1', optional = False),
            requirements.IntRequirement(name = 'translation_control_register', optional = False),
            requirements.IntRequirement(name = 'kernel_virtual_offset', optional = True),
            requirements.StringRequirement(name = 'kernel_banner', optional = True)
        ]

    @classproperty
    def minimum_address(cls) -> int:
        return 0

    @classproperty
    def maximum_address(cls) -> int:
        return (1 << cls._maxvirtaddr) - 1
