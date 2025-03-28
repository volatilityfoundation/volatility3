# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

import collections
import functools
import logging
import math
import struct
from typing import Any, Dict, Iterable, List, Optional, Tuple

from volatility3 import classproperty
from volatility3.framework import exceptions, interfaces, constants
from volatility3.framework.configuration import requirements
from volatility3.framework.layers import linear

vollog = logging.getLogger(__name__)

INTEL_TRANSLATION_DEBUGGING = False


class Intel(linear.LinearlyMappedLayer):
    """Translation Layer for the Intel IA32 memory mapping."""

    _PAGE_BIT_PRESENT = 0
    _PAGE_BIT_PSE = 7  # Page Size Extension: 4 MB (or 2MB) page
    _PAGE_BIT_PROTNONE = 8
    _PAGE_BIT_PAT_LARGE = 12  # 2MB or 1GB pages

    _PAGE_PRESENT = 1 << _PAGE_BIT_PRESENT
    _PAGE_PSE = 1 << _PAGE_BIT_PSE
    _PAGE_PROTNONE = 1 << _PAGE_BIT_PROTNONE
    _PAGE_PAT_LARGE = 1 << _PAGE_BIT_PAT_LARGE

    _entry_format = "<I"
    _page_size_in_bits = 12
    _bits_per_register = 32
    # NOTE: _maxphyaddr is MAXPHYADDR as defined in the Intel specs *NOT* the maximum physical address
    _maxphyaddr = 32
    _maxvirtaddr = _maxphyaddr
    _structure = [("page directory", 10, False), ("page table", 10, True)]
    _direct_metadata = collections.ChainMap(
        {"architecture": "Intel32"},
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
        """Page shift for the intel memory layers."""
        return cls._page_size_in_bits

    @classproperty
    @functools.lru_cache
    def page_size(cls) -> int:
        """Page size for the intel memory layers.

        All Intel layers work on 4096 byte pages
        """
        return 1 << cls._page_size_in_bits

    @classproperty
    @functools.lru_cache
    def page_mask(cls) -> int:
        """Page mask for the intel memory layers."""
        return ~(cls.page_size - 1)

    @classproperty
    @functools.lru_cache
    def bits_per_register(cls) -> int:
        """Returns the bits_per_register to determine the range of an
        IntelTranslationLayer."""
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
        """Returns whether a particular page is valid based on its entry."""
        return bool(entry & 1)

    @staticmethod
    def _page_is_dirty(entry: int) -> bool:
        """Returns whether a particular page is dirty based on its entry."""
        return bool(entry & (1 << 6))

    def canonicalize(self, addr: int) -> int:
        """Canonicalizes an address by performing an appropiate sign extension on the higher addresses"""
        if self._bits_per_register <= self._maxvirtaddr:
            return addr & self.address_mask
        elif addr < (1 << self._maxvirtaddr - 1):
            return addr
        return self._mask(addr, self._maxvirtaddr, 0) + self._canonical_prefix

    def decanonicalize(self, addr: int) -> int:
        """Removes canonicalization to ensure an address fits within the correct range if it has been canonicalized

        This will produce an address outside the range if the canonicalization is incorrect
        """
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
    def _translate_entry(self, page_address: int) -> int:
        """Translates a page address based on paging tables.

        Args:
            page_address: The page base address

        Returns:
            the translated entry value
        """
        # Setup the entry and how far we are through the offset
        # Position maintains the number of bits left to process
        # We or with 0x1 to ensure our page_map_offset is always valid
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
            # Check if we're a large page
            if large_page and (entry & self._PAGE_PSE):
                # Mask off the PAT bit
                if entry & self._PAGE_PAT_LARGE:
                    entry -= self._PAGE_PAT_LARGE
                # We're a large page, the rest is finished below
                # If we want to implement PSE-36, it would need to be done here
                break
            # Figure out how much of the offset we should be using
            start = position
            position -= size
            index = self._mask(page_address, start, position + 1) >> (position + 1)

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

            # Read the data for the next entry
            entry_data_start = index << self._index_shift
            entry_data = table[entry_data_start : entry_data_start + self._entry_size]

            if INTEL_TRANSLATION_DEBUGGING:
                vollog.log(
                    constants.LOGLEVEL_VVVV,
                    f"Entry {hex(entry)} at index {hex(index)} gives data {hex(struct.unpack(self._entry_format, entry_data)[0])} as {name}",
                )

            # Read out the new entry from memory
            (entry,) = struct.unpack(self._entry_format, entry_data)

        return entry, position

    @functools.lru_cache(maxsize=1025)
    def _get_valid_table(self, base_address: int) -> Optional[bytes]:
        """Extracts the table, validates it and returns it if it's valid."""
        table = self._context.layers.read(
            self._base_layer, base_address, self.page_size
        )

        # If the table is entirely duplicates, then mark the whole table as bad
        if table == table[: self._entry_size] * self._entry_number:
            return None
        return table

    def is_valid(self, offset: int, length: int = 1) -> bool:
        """Returns whether the address offset can be translated to a valid
        address."""
        try:
            # TODO: Consider reimplementing this, since calls to mapping can call is_valid
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
                    yield stashed_offset, stashed_size, stashed_mapped_offset, stashed_mapped_size, stashed_map_layer
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
            yield stashed_offset, stashed_size, stashed_mapped_offset, stashed_mapped_size, stashed_map_layer

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
            try:
                chunk_offset, page_size, layer_name = self._translate(offset)
                chunk_size = min(page_size - (chunk_offset % page_size), length)
                if not self._context.layers[layer_name].is_valid(
                    chunk_offset, chunk_size
                ):
                    raise exceptions.InvalidAddressException(
                        layer_name=layer_name, invalid_address=chunk_offset
                    )
            except (
                exceptions.PagedInvalidAddressException,
                exceptions.InvalidAddressException,
            ) as excp:
                if not ignore_errors:
                    raise
                # We can jump more if we know where the page fault failed
                if isinstance(excp, exceptions.PagedInvalidAddressException):
                    mask = (1 << excp.invalid_bits) - 1
                else:
                    mask = (1 << self._page_size_in_bits) - 1
                length_diff = mask + 1 - (offset & mask)
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


class IntelPAE(Intel):
    """Class for handling Physical Address Extensions for Intel
    architectures."""

    _entry_format = "<Q"
    _bits_per_register = 32
    _maxphyaddr = 40
    _maxvirtaddr = 32
    _structure = [
        ("page directory pointer", 2, False),
        ("page directory", 9, True),
        ("page table", 9, True),
    ]
    _direct_metadata = collections.ChainMap({"pae": True}, Intel._direct_metadata)


class Intel32e(Intel):
    """Class for handling 64-bit (32-bit extensions) for Intel
    architectures."""

    _direct_metadata = collections.ChainMap(
        {"architecture": "Intel64"}, Intel._direct_metadata
    )
    _entry_format = "<Q"
    _bits_per_register = 64
    _maxphyaddr = 52
    _maxvirtaddr = 48
    _structure = [
        ("page map layer 4", 9, False),
        ("page directory pointer", 9, True),
        ("page directory", 9, True),
        ("page table", 9, True),
    ]


class WindowsMixin(Intel):
    @staticmethod
    def _page_is_valid(entry: int) -> bool:
        """Returns whether a particular page is valid based on its entry.

        Windows uses additional "available" bits to store flags
        These flags allow windows to determine whether a page is still valid

        Bit 11 is the transition flag, and Bit 10 is the prototype flag

        For more information, see Windows Internals (6th Ed, Part 2, pages 268-269)
        """
        return bool((entry & 1) or ((entry & 1 << 11) and not entry & 1 << 10))

    def _translate_swap(
        self, layer: Intel, offset: int, bit_offset: int
    ) -> Tuple[int, int, str]:
        try:
            return super()._translate(offset)
        except exceptions.PagedInvalidAddressException as excp:
            entry = excp.entry
            tbit = bool(entry & (1 << 11))
            pbit = bool(entry & (1 << 10))
            unknown_bit = bool(entry & (1 << 7))
            n = (entry >> 1) & 0xF
            vbit = bool(entry & 1)
            if (not tbit and not pbit and not vbit and unknown_bit) and (
                (entry >> bit_offset) != 0
            ):
                swap_offset = entry >> bit_offset << excp.invalid_bits

                if layer.config.get("swap_layers", False):
                    swap_layer_name = layer.config.get(
                        interfaces.configuration.path_join(
                            "swap_layers", "swap_layers" + str(n)
                        ),
                        None,
                    )
                    if swap_layer_name:
                        return swap_offset, 1 << excp.invalid_bits, swap_layer_name
                raise exceptions.SwappedInvalidAddressException(
                    layer_name=excp.layer_name,
                    invalid_address=excp.invalid_address,
                    invalid_bits=excp.invalid_bits,
                    entry=excp.entry,
                    swap_offset=swap_offset,
                )
            raise


### These must be full separate classes so that JSON configs re-create them properly


class WindowsIntel(WindowsMixin, Intel):
    def _translate(self, offset):
        return self._translate_swap(self, offset, self._page_size_in_bits)


class WindowsIntelPAE(WindowsMixin, IntelPAE):
    def _translate(self, offset: int) -> Tuple[int, int, str]:
        return self._translate_swap(self, offset, self._bits_per_register)


class WindowsIntel32e(WindowsMixin, Intel32e):
    # TODO: Fix appropriately in a future release.
    # Currently just a temporary workaround to deal with custom bit flag
    # in the PFN field for pages in transition state.
    # See https://github.com/volatilityfoundation/volatility3/pull/475
    _maxphyaddr = 45

    def _translate(self, offset: int) -> Tuple[int, int, str]:
        return self._translate_swap(self, offset, self._bits_per_register // 2)


class LinuxMixin(Intel):
    @functools.cached_property
    def _register_mask(self) -> int:
        return (1 << self._bits_per_register) - 1

    @functools.cached_property
    def _physical_mask(self) -> int:
        # From kernels 4.18 the physical mask is dynamic: See AMD SME, Intel Multi-Key Total
        # Memory Encryption and CONFIG_DYNAMIC_PHYSICAL_MASK: 94d49eb30e854c84d1319095b5dd0405a7da9362
        physical_mask = (1 << self._maxphyaddr) - 1
        # TODO: Come back once SME support is available in the framework
        return physical_mask

    @functools.cached_property
    def page_mask(self) -> int:
        # Note that within the Intel class it's a class method. However, since it uses
        # complement operations and we are working in Python, it would be more careful to
        # limit it to the architecture's pointer size.
        return ~(self.page_size - 1) & self._register_mask

    @functools.cached_property
    def _physical_page_mask(self) -> int:
        return self.page_mask & self._physical_mask

    @functools.cached_property
    def _pte_pfn_mask(self) -> int:
        return self._physical_page_mask

    @functools.cached_property
    def _pte_flags_mask(self) -> int:
        return ~self._pte_pfn_mask & self._register_mask

    def _pte_flags(self, pte) -> int:
        return pte & self._pte_flags_mask

    def _is_pte_present(self, entry: int) -> bool:
        return (
            self._pte_flags(entry) & (self._PAGE_PRESENT | self._PAGE_PROTNONE)
        ) != 0

    def _page_is_valid(self, entry: int) -> bool:
        # Overrides the Intel static method with the Linux-specific implementation
        return self._is_pte_present(entry)

    def _pte_needs_invert(self, entry) -> bool:
        # Entries that were set to PROT_NONE (PAGE_PRESENT) are inverted
        # A clear PTE shouldn't be inverted. See f19f5c4
        return entry and not (entry & self._PAGE_PRESENT)

    def _protnone_mask(self, entry: int) -> int:
        """Gets a mask to XOR with the page table entry to get the correct PFN"""
        return self._register_mask if self._pte_needs_invert(entry) else 0

    def _pte_pfn(self, entry: int) -> int:
        """Extracts the page frame number from the page table entry"""
        pfn = entry ^ self._protnone_mask(entry)
        return (pfn & self._pte_pfn_mask) >> self.page_shift


class LinuxIntel(LinuxMixin, Intel):
    pass


class LinuxIntelPAE(LinuxMixin, IntelPAE):
    pass


class LinuxIntel32e(LinuxMixin, Intel32e):
    # In the Linux kernel, the __PHYSICAL_MASK_SHIFT is a mask used to extract the
    # physical address from a PTE. In Volatility3, this is referred to as _maxphyaddr.
    #
    # Until kernel version 4.17, Linux x86-64 used a 46-bit mask. With commit
    # b83ce5ee91471d19c403ff91227204fb37c95fb2, this was extended to 52 bits,
    # applying to both 4 and 5-level page tables.
    #
    # We initially used 52 bits for all Intel 64-bit systems, but this produced incorrect
    # results for PROT_NONE pages. Since the mask value is defined by a preprocessor macro,
    # it's difficult to detect the exact bit shift used in the current kernel.
    # Using 46 bits has proven reliable for our use case, as seen in tools like crashtool.
    _maxphyaddr = 46
