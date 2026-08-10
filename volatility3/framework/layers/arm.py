# This file is Copyright 2024 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

import collections
import functools
import logging
import math
import struct
from typing import Any, Dict, Iterable, List, Optional, Tuple

from volatility3 import classproperty
from volatility3.framework import constants, exceptions, interfaces
from volatility3.framework.configuration import requirements
from volatility3.framework.layers import linear

vollog = logging.getLogger(__name__)

AARCH64_TRANSLATION_DEBUGGING = False


class AArch64(linear.LinearlyMappedLayer):
    """Translation Layer for AArch64 (ARM64) memory mapping.

    Supports 4KB granule with 39-bit, 48-bit, and 52-bit virtual address spaces.
    """

    _entry_format = "<Q"
    _page_size_in_bits = 12
    _bits_per_register = 64
    # Subclasses must define _maxphyaddr, _maxvirtaddr, _structure
    _maxphyaddr = 48
    _maxvirtaddr = 48
    _structure = []
    _direct_metadata = collections.ChainMap(
        {"architecture": "AArch64"},
        {"mapped": True},
        interfaces.layers.TranslationLayerInterface._direct_metadata,
    )

    def __init__(
        self,
        context: interfaces.context.ContextInterface,
        config_path: str,
        name: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__(
            context=context, config_path=config_path, name=name, metadata=metadata
        )
        self._base_layer = self.config["memory_layer"]
        self._swap_layers: List[str] = []
        self._page_map_offset = self.config["page_map_offset"]

        # Assign constants
        self._initial_position = min(self._maxvirtaddr, self._bits_per_register) - 1
        self._initial_entry = (
            self._mask(self._page_map_offset, self._initial_position, 0) | 0x1
        )
        self._entry_size = struct.calcsize(self._entry_format)
        self._entry_number = self.page_size // self._entry_size
        self._canonical_prefix = self._mask(
            (1 << self._bits_per_register) - 1,
            self._bits_per_register,
            self._maxvirtaddr,
        )

        # These can vary depending on the type of space
        self._index_shift = math.ceil(math.log2(struct.calcsize(self._entry_format)))

    @classproperty
    @functools.lru_cache
    def page_shift(cls) -> int:
        """Page shift for the AArch64 memory layers."""
        return cls._page_size_in_bits

    @classproperty
    @functools.lru_cache
    def page_size(cls) -> int:
        """Page size for the AArch64 memory layers (4KB)."""
        return 1 << cls._page_size_in_bits

    @classproperty
    @functools.lru_cache
    def page_mask(cls) -> int:
        """Page mask for the AArch64 memory layers."""
        return ~(cls.page_size - 1)

    @classproperty
    @functools.lru_cache
    def bits_per_register(cls) -> int:
        """Returns the bits_per_register to determine the range of an
        AArch64TranslationLayer."""
        return cls._bits_per_register

    @classproperty
    @functools.lru_cache
    def minimum_address(cls) -> int:
        return 0

    @classproperty
    @functools.lru_cache
    def maximum_address(cls) -> int:
        return (1 << cls._maxvirtaddr) - 1

    @classproperty
    def structure(cls) -> List[Tuple[str, int, bool]]:
        return cls._structure

    @staticmethod
    def _mask(value: int, high_bit: int, low_bit: int) -> int:
        """Returns the bits of a value between highbit and lowbit inclusive."""
        high_mask = (1 << (high_bit + 1)) - 1
        low_mask = (1 << low_bit) - 1
        mask = high_mask ^ low_mask
        return value & mask

    @staticmethod
    def _page_is_valid(entry: int) -> bool:
        """Returns whether a particular page is valid based on its entry.

        ARM64 PTE_VALID is bit 0.
        """
        return bool(entry & 0x1)

    @staticmethod
    def _page_is_dirty(entry: int) -> bool:
        """Returns whether a particular page is dirty based on its entry.

        ARM64 uses bit 51 (PTE_DBM / hardware dirty bit).
        """
        return bool(entry & (1 << 51))

    def canonicalize(self, addr: int) -> int:
        """Canonicalizes an address by performing an appropriate sign extension on the higher addresses"""
        if self._bits_per_register <= self._maxvirtaddr:
            return addr & self.address_mask
        elif addr < (1 << self._maxvirtaddr - 1):
            return addr
        return self._mask(addr, self._maxvirtaddr, 0) + self._canonical_prefix

    def decanonicalize(self, addr: int) -> int:
        """Removes canonicalization to ensure an address fits within the correct range"""
        if addr < (1 << self._maxvirtaddr - 1):
            return addr
        return addr ^ self._canonical_prefix

    def _translate(self, offset: int) -> Tuple[int, int, str]:
        """Translates a specific offset based on paging tables.

        Returns the translated offset, the contiguous pagesize that the
        translated address lives in and the layer_name that the address
        lives in
        """
        entry, position = self._translate_entry(offset & self.page_mask)

        # Now we're done
        if not self._page_is_valid(entry):
            raise exceptions.PagedInvalidAddressException(
                self.name,
                offset,
                position + 1,
                entry,
                f"Page Fault at entry {hex(entry)} in page entry",
            )

        pfn = self._pte_pfn(entry)
        page_offset = self._mask(offset, position, 0)
        page = pfn << self.page_shift | page_offset

        return page, 1 << (position + 1), self._base_layer

    def _pte_pfn(self, entry: int) -> int:
        """Extracts the page frame number (PFN) from the page table entry (PTE) entry"""
        return self._mask(entry, self._maxphyaddr - 1, 0) >> self.page_shift

    @functools.lru_cache(maxsize=1024)
    def _translate_entry(self, page_address: int) -> Tuple[int, int]:
        """Translates a page address based on paging tables.

        Args:
            page_address: The page base address

        Returns:
            the translated entry value and position
        """
        # Setup the entry and how far we are through the offset
        position = self._initial_position
        entry = self._initial_entry

        if not (
            self.minimum_address
            <= (page_address & self.address_mask)
            <= self.maximum_address
        ):
            raise exceptions.PagedInvalidAddressException(
                self.name,
                page_address,
                position + 1,
                entry,
                "Entry outside virtual address range: " + hex(entry),
            )

        # Run through the offset in various chunks
        for name, size, large_page in self._structure:
            # Check we're valid
            if not self._page_is_valid(entry):
                raise exceptions.PagedInvalidAddressException(
                    self.name,
                    page_address,
                    position + 1,
                    entry,
                    "Page Fault at entry " + hex(entry) + " in table " + name,
                )

            # Grab the base address of the table we'll be getting the next entry from
            base_address = self._mask(
                entry, self._maxphyaddr - 1, size + self._index_shift
            )

            table = self._get_valid_table(base_address)
            if table is None:
                raise exceptions.PagedInvalidAddressException(
                    self.name,
                    page_address,
                    position + 1,
                    entry,
                    "Page Fault at entry " + hex(entry) + " in table " + name,
                )

            # Figure out how much of the offset we should be using
            start = position
            position -= size
            index = self._mask(page_address, start, position + 1) >> (position + 1)

            # Read the data for the next entry
            entry_data_start = index << self._index_shift
            entry_data = table[entry_data_start : entry_data_start + self._entry_size]

            if AARCH64_TRANSLATION_DEBUGGING:
                vollog.log(
                    constants.LOGLEVEL_VVVV,
                    f"Entry {hex(entry)} at index {hex(index)} gives data {hex(struct.unpack(self._entry_format, entry_data)[0])} as {name}",
                )

            # Read out the new entry from memory
            (entry,) = struct.unpack(self._entry_format, entry_data)

            # Check if we're a block descriptor (large page)
            # ARM64: (entry & 0x3) == 0x1 means block descriptor (valid but not table)
            # This is the ARM64 equivalent of Intel's PSE bit
            if large_page and (entry & 0x3) == 0x1:
                # We're a block descriptor, the rest is finished below
                break

        return entry, position

    @functools.lru_cache(maxsize=1025)
    def _get_valid_table(self, base_address: int) -> Optional[bytes]:
        """Extracts the table, validates it and returns it if it's valid."""
        try:
            table = self._context.layers.read(
                self._base_layer, base_address, self.page_size
            )
        except exceptions.InvalidAddressException:
            # Some memory capture tools (e.g., AVML) have off-by-one errors
            # in segment boundaries, causing reads at the end of a segment to
            # fail for the last few bytes. Use padded read as a fallback.
            try:
                table = self._context.layers.read(
                    self._base_layer, base_address, self.page_size, pad=True
                )
            except exceptions.InvalidAddressException:
                return None

        # If the table is entirely duplicates, then mark the whole table as bad
        if table == table[: self._entry_size] * self._entry_number:
            return None
        return table

    def is_valid(self, offset: int, length: int = 1) -> bool:
        """Returns whether the address offset can be translated to a valid
        address."""
        try:
            return all(
                self._context.layers[layer].is_valid(mapped_offset)
                for _, _, mapped_offset, _, layer in self.mapping(offset, length)
            )
        except exceptions.InvalidAddressException:
            return False

    def is_dirty(self, offset: int) -> bool:
        """Returns whether the page at offset is marked dirty"""
        return self._page_is_dirty(self._translate_entry(offset & self.page_mask)[0])

    def mapping(
        self, offset: int, length: int, ignore_errors: bool = False
    ) -> Iterable[Tuple[int, int, int, int, str]]:
        """Returns a sorted iterable of (offset, sublength, mapped_offset, mapped_length, layer)
        mappings.

        This allows translation layers to provide maps of contiguous
        regions in one layer
        """
        stashed_offset = stashed_mapped_offset = stashed_size = stashed_mapped_size = (
            stashed_map_layer
        ) = None
        for offset, size, mapped_offset, mapped_size, map_layer in self._mapping(
            offset, length, ignore_errors
        ):
            if (
                stashed_offset is None
                or (stashed_offset + stashed_size != offset)
                or (stashed_mapped_offset + stashed_mapped_size != mapped_offset)
                or (stashed_map_layer != map_layer)
            ):
                # The block isn't contiguous
                if stashed_offset is not None:
                    yield (
                        stashed_offset,
                        stashed_size,
                        stashed_mapped_offset,
                        stashed_mapped_size,
                        stashed_map_layer,
                    )
                # Update all the stashed values after output
                stashed_offset = offset
                stashed_mapped_offset = mapped_offset
                stashed_size = size
                stashed_mapped_size = mapped_size
                stashed_map_layer = map_layer
            else:
                # Part of an existing block
                stashed_size += size
                stashed_mapped_size += mapped_size
        # Yield whatever's left
        if (
            stashed_offset is not None
            and stashed_mapped_offset is not None
            and stashed_size is not None
            and stashed_mapped_size is not None
            and stashed_map_layer is not None
        ):
            yield (
                stashed_offset,
                stashed_size,
                stashed_mapped_offset,
                stashed_mapped_size,
                stashed_map_layer,
            )

    def _mapping(
        self, offset: int, length: int, ignore_errors: bool = False
    ) -> Iterable[Tuple[int, int, int, int, str]]:
        """Returns a sorted iterable of (offset, sublength, mapped_offset, mapped_length, layer)
        mappings.

        This allows translation layers to provide maps of contiguous
        regions in one layer
        """
        if length == 0:
            try:
                mapped_offset, _, layer_name = self._translate(offset)
                if not self._context.layers[layer_name].is_valid(mapped_offset):
                    raise exceptions.InvalidAddressException(
                        layer_name=layer_name, invalid_address=mapped_offset
                    )
            except exceptions.InvalidAddressException:
                if not ignore_errors:
                    raise
                return None
            yield offset, length, mapped_offset, length, layer_name
            return None
        while length > 0:
            skip_mask = None
            try:
                chunk_offset, page_size, layer_name = self._translate(offset)
                # Page align the chunk size value
                chunk_size = min(page_size - (offset % page_size), length)
                if not self._context.layers[layer_name].is_valid(
                    chunk_offset, chunk_size
                ):
                    skip_mask = chunk_size - 1
                    raise exceptions.InvalidAddressException(
                        layer_name=layer_name, invalid_address=chunk_offset
                    )
            except (
                exceptions.PagedInvalidAddressException,
                exceptions.InvalidAddressException,
            ) as excp:
                if not ignore_errors:
                    raise
                if skip_mask is None:
                    if isinstance(excp, exceptions.PagedInvalidAddressException):
                        skip_mask = (1 << excp.invalid_bits) - 1
                    else:
                        skip_mask = (1 << self._page_size_in_bits) - 1
                length_diff = skip_mask + 1 - (offset & skip_mask)
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
        return [self._base_layer] + self._swap_layers

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.TranslationLayerRequirement(
                name="memory_layer", optional=False
            ),
            requirements.LayerListRequirement(name="swap_layers", optional=True),
            requirements.IntRequirement(name="page_map_offset", optional=False),
            requirements.IntRequirement(name="kernel_virtual_offset", optional=True),
            requirements.StringRequirement(name="kernel_banner", optional=True),
        ]


class AArch64_39(AArch64):
    """AArch64 with 39-bit virtual address space, 3-level page table (4KB granule)."""

    _maxphyaddr = 48
    _maxvirtaddr = 39
    _structure = [
        ("level 1 table", 9, True),
        ("level 2 table", 9, True),
        ("level 3 table", 9, False),
    ]


class AArch64_48(AArch64):
    """AArch64 with 48-bit virtual address space, 4-level page table (4KB granule)."""

    _maxphyaddr = 48
    _maxvirtaddr = 48
    _structure = [
        ("level 0 table", 9, False),
        ("level 1 table", 9, True),
        ("level 2 table", 9, True),
        ("level 3 table", 9, False),
    ]


class AArch64_52(AArch64):
    """AArch64 with 52-bit virtual address space, 5-level page table (4KB granule)."""

    _maxphyaddr = 52
    _maxvirtaddr = 52
    _structure = [
        ("level -1 table", 4, False),
        ("level 0 table", 9, False),
        ("level 1 table", 9, True),
        ("level 2 table", 9, True),
        ("level 3 table", 9, False),
    ]


class LinuxAArch64(AArch64):
    """Linux-specific AArch64 PTE handling.

    Handles PROT_NONE pages where PTE_VALID (bit 0) is clear but
    PTE_PRESENT_INVALID (bit 11, PTE_NG) is set.
    No PTE inversion is needed (ARM64 Linux does not use XOR inversion like x86).
    """

    @staticmethod
    def _page_is_valid(entry: int) -> bool:
        """Returns whether a particular page is valid based on its entry.

        ARM64 Linux page presence check:
        - PTE_VALID (bit 0) set, OR
        - PTE_PRESENT_INVALID (bit 11) set with PTE_VALID clear
          (used for PROT_NONE pages)

        See arch/arm64/include/asm/pgtable.h pte_present()
        """
        PTE_VALID = 1 << 0
        PTE_PRESENT_INVALID = 1 << 11
        if entry & PTE_VALID:
            return True
        return (entry & (PTE_PRESENT_INVALID | PTE_VALID)) == PTE_PRESENT_INVALID


### These must be full separate classes so that JSON configs re-create them properly


class LinuxAArch64_39(LinuxAArch64, AArch64_39):
    pass


class LinuxAArch64_48(LinuxAArch64, AArch64_48):
    pass


class LinuxAArch64_52(LinuxAArch64, AArch64_52):
    pass
