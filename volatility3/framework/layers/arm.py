# This file is Copyright 2024 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

import logging
import functools
import collections
import json
import inspect
import struct
from typing import Optional, Dict, Any, List, Iterable, Tuple
from enum import Enum

from volatility3 import classproperty
from volatility3.framework import interfaces, exceptions
from volatility3.framework.configuration import requirements
from volatility3.framework.layers import linear
from volatility3.framework.interfaces.configuration import path_join

vollog = logging.getLogger(__name__)

"""
Webography :
 [1] Arm, "Arm Architecture Reference Manual for A-profile architecture, DDI 0487J.a (ID042523)", https://developer.arm.com/documentation/ddi0487/ja/?lang=en
 [2] Linux, Linux Kernel source code, v6.7
 [3] Arm, "Programmer's Guide for ARMv8-A", https://cs140e.sergio.bz/docs/ARMv8-A-Programmer-Guide.pdf

Glossary :
 TTB : Translation Table Base
 TCR : Translation Control Register
 EL : Exception Level (0:Application,1:Kernel,2:Hypervisor,3:Secure Monitor)
 Granule : Translation granule (smallest block of memory that can be described)

Definitions :

 The OS-controlled translation is called stage 1 translation, and the hypervisor-controlled translation is called stage 2 translation.

Notes :
 If hardware management of the dirty state is enabled, the DBM bit is set to 1. ([1], D8.4.6)
 If hardware management of the Access Flag bit is not enabled, software must implement it. ([1], D8.4.5)
 Access Permissions bits can be updated by hardware in some situations, but is mostly managed by software. ([1], D8.4.3)
"""


class AArch64Exception(exceptions.LayerException):
    pass


class AArch64(linear.LinearlyMappedLayer):
    """Translation Layer for the Arm AArch64 memory mapping.

    This layer can be instantiated in two contexts : Low space (user land), High space (kernel land).
    """

    _direct_metadata = collections.ChainMap(
        {"architecture": "AArch64"},
        {"mapped": True},
        interfaces.layers.TranslationLayerInterface._direct_metadata,
    )

    _bits_per_register = 64
    _register_size = _bits_per_register // 8
    # NOTE: _maxphyaddr is as defined in the AArch64 specs *NOT* the maximum physical address
    # _maxvirtaddr actually depends on the context
    # We need the full 64 bits masking on addresses to determine their TTB at bit 55
    _maxphyaddr = 64
    _maxvirtaddr = _maxphyaddr

    # [1], see D8.2.7 to D8.2.9, starting at page 5828
    _granules_indexes = {
        4: [(51, 48), (47, 39), (38, 30), (29, 21), (20, 12)],
        16: [(51, 47), (46, 36), (35, 25), (24, 14)],
        64: [(51, 42), (41, 29), (28, 16)],
    }

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
        self._cpu_regs = {}
        for register in [
            AArch64RegMap.TCR_EL1.__name__,
            AArch64RegMap.TTBR1_EL1.__name__,
            AArch64RegMap.ID_AA64MMFR1_EL1.__name__,
        ]:
            # Sanity check for optional registers.
            # Missing required CPU registers will have
            # previously raised a layer requirement exception.
            if self.config.get(register):
                self._cpu_regs[register] = self.config[register]

        self._cpu_regs_mapped = self._map_reg_values(self._cpu_regs)
        self._entry_format = self.config["entry_format"]
        self._layer_debug = self.config.get("layer_debug", False)
        self._translation_debug = self.config.get("translation_debug", False)
        self._base_layer = self.config["memory_layer"]
        # self._swap_layers = []  # TODO
        self._page_map_offset = self.config["page_map_offset"]
        self._page_map_offset_kernel = self._read_register_field(
            AArch64RegMap.TTBR1_EL1.BADDR
        )
        self._ttbs_tnsz = [
            self._read_register_field(AArch64RegMap.TCR_EL1.T0SZ),
            self._read_register_field(AArch64RegMap.TCR_EL1.T1SZ),
        ]
        self._ttbs_granules = [
            AArch64RegFieldValues._get_ttbr0_el1_granule_size(
                self._read_register_field(AArch64RegMap.TCR_EL1.TG0)
            ),
            AArch64RegFieldValues._get_ttbr1_el1_granule_size(
                self._read_register_field(AArch64RegMap.TCR_EL1.TG1)
            ),
        ]

        # Context : TTB0 (user space) or TTB1 (kernel space)
        self._virtual_addr_space = int(
            self._page_map_offset == self._page_map_offset_kernel
        )

        # [1], see D8.1.9, page 5818
        self._ttb_bitsize = 64 - self._ttbs_tnsz[self._virtual_addr_space]
        self._ttb_granule = self._ttbs_granules[self._virtual_addr_space]
        self._page_size = self._ttb_granule * 1024
        self._page_size_in_bits = self._page_size.bit_length() - 1
        """
        Translation Table Granule is in fact the page size, as it is the
        smallest block of memory that can be described.
        Possibles values are 4, 16 or 64 (kB).
        """

        # 52 bits VA detection
        self._is_52bits = True if self._ttb_bitsize < 16 else False
        # [1], see D8.3, page 5852
        if self._is_52bits:
            if self._ttb_granule in [4, 16]:
                self._ta_51_x_bits = (9, 8)
            elif self._ttb_granule == 64:
                self._ta_51_x_bits = (15, 12)

        # Translation indexes calculations
        self._ttb_lookup_indexes = self._determine_ttb_lookup_indexes(
            self._ttb_granule, self._ttb_bitsize
        )
        self._ttb_descriptor_bits = self._determine_ttb_descriptor_bits(
            self._ttb_granule, self._ttb_lookup_indexes, self._is_52bits
        )

        self._virtual_addr_range = self._get_virtual_addr_range()
        self._canonical_prefix = self._mask(
            (1 << self._bits_per_register) - 1,
            self._bits_per_register,
            self._ttb_bitsize,
        )

        self._entry_size = struct.calcsize(self._entry_format)
        self._entry_number = self._page_size // self._entry_size

        # CPU features
        hafdbs = self._read_register_field(AArch64RegMap.ID_AA64MMFR1_EL1.HAFDBS, True)
        if hafdbs:
            self._feat_hafdbs = AArch64RegFieldValues._get_feature_HAFDBS(hafdbs)
        else:
            self._feat_hafdbs = None

        if self._layer_debug:
            self._print_layer_debug_informations()

    def _print_layer_debug_informations(self) -> None:
        vollog.debug(f"Base layer : {self._base_layer}")
        vollog.debug(
            f"Virtual address space : {'kernel' if self._virtual_addr_space else 'user'}"
        )
        vollog.debug(
            f"Virtual addresses space range : {tuple([hex(x) for x in self._get_virtual_addr_range()])}"
        )
        vollog.debug(f"Page size : {self._ttb_granule}")
        vollog.debug(f"T{self._virtual_addr_space}SZ : {self._ttb_bitsize}")
        vollog.debug(f"Page map offset : {hex(self._page_map_offset)}")
        vollog.debug(f"Translation mappings : {self._ttb_lookup_indexes}")

        return None

    @classmethod
    def _determine_ttb_descriptor_bits(
        cls, ttb_granule: int, ttb_lookup_indexes: int, is_52bits: bool
    ) -> Tuple[int]:
        """Returns the descriptor bits to extract from a descriptor (high and low)

        Example with granule = 4 kB without 52 bits :
            (47,12)
        Example with granule = 16 kB and 52 bits :
            (49,14)
        """

        # [1], see D8.3, page 5852
        return (
            49 if ttb_granule in [4, 16] and is_52bits else 47,
            ttb_lookup_indexes[-1][1],
        )

    @classmethod
    def _determine_ttb_lookup_indexes(
        cls, ttb_granule: int, ttb_bitsize: int
    ) -> List[Tuple[int]]:
        """Returns the bits to extract from a translation address (highs and lows)

        Example with bitsize = 47 and granule = 4 kB :
            indexes = [(51, 48), (47, 39), (38, 30), (29, 21), (20, 12)]
            result = [(46, 39), (38, 30), (29, 21), (20, 12)]
        """
        indexes = [
            index
            for index in cls._granules_indexes[ttb_granule]
            if ttb_bitsize > index[1]
        ]
        indexes[0] = (ttb_bitsize - 1, indexes[0][1])

        return indexes

    def _translate(self, virtual_offset: int) -> Tuple[int, int, str]:
        """Translates a specific offset based on paging tables.

        Returns the translated offset, the contiguous pagesize that the
        translated address lives in and the layer_name that the address
        lives in
        """
        table_address, position, _ = self._translate_entry(virtual_offset)
        offset_within_page = self._mask(virtual_offset, position - 1, 0)
        physical_offset = table_address + offset_within_page

        return physical_offset, 2**position, self._base_layer

    def _translate_entry(self, virtual_offset: int) -> Tuple[int, int, int]:
        """Translates a virtual offset to a physical one within this segment
        Returns the translated address, the maximum offset within the block and the page
        the translated address lives in
        """
        base_layer = self.context.layers[self._base_layer]

        # [1], see D8.2.4, page 5825
        ttb_selector = self._mask(virtual_offset, 55, 55)

        # Check if requested address belongs to the virtual memory space context
        if ttb_selector != self._virtual_addr_space:
            raise exceptions.InvalidAddressException(
                layer_name=self.name,
                invalid_address=virtual_offset,
            )

        table_address = self._page_map_offset
        max_level = len(self._ttb_lookup_indexes) - 1
        for level, (high_bit, low_bit) in enumerate(self._ttb_lookup_indexes):
            index = self._mask(virtual_offset, high_bit, low_bit)
            (descriptor,) = struct.unpack(
                self._entry_format,
                base_layer.read(
                    table_address + (index * self._register_size), self._register_size
                ),
            )
            table_address = 0
            # Bits 51->x need to be extracted from the descriptor
            if self._is_52bits:
                ta_51_x = self._mask(
                    descriptor,
                    self._ta_51_x_bits[0],
                    self._ta_51_x_bits[1],
                )
                table_address = ta_51_x << (52 - ta_51_x.bit_length())

            # [1], see D8.3, page 5852
            descriptor_type = self._mask(descriptor, 1, 0)
            # Table descriptor
            if level < max_level and descriptor_type == 0b11:
                table_address |= (
                    self._mask(
                        descriptor,
                        self._ttb_descriptor_bits[0],
                        self._ttb_descriptor_bits[1],
                    )
                    << self._ttb_descriptor_bits[1]
                )
                if self._get_valid_table(table_address) is None:
                    raise exceptions.PagedInvalidAddressException(
                        layer_name=self.name,
                        invalid_address=virtual_offset,
                        invalid_bits=low_bit,
                        entry=descriptor,
                    )
            # Block descriptor
            elif level < max_level and descriptor_type == 0b01:
                table_address |= (
                    self._mask(
                        descriptor,
                        self._ttb_descriptor_bits[0],
                        low_bit,
                    )
                    << low_bit
                )
                break
            # Page descriptor
            elif level == max_level and descriptor_type == 0b11:
                table_address |= (
                    self._mask(
                        descriptor,
                        self._ttb_descriptor_bits[0],
                        self._ttb_descriptor_bits[1],
                    )
                    << self._ttb_descriptor_bits[1]
                )
                break
            # Invalid descriptor || Reserved descriptor (level 3)
            else:
                raise exceptions.PagedInvalidAddressException(
                    layer_name=self.name,
                    invalid_address=virtual_offset,
                    invalid_bits=low_bit,
                    entry=descriptor,
                )

        if self._translation_debug:
            vollog.debug(
                f"Virtual {hex(virtual_offset)} lives in page frame {hex(table_address)} at offset {hex(self._mask(virtual_offset, low_bit-1, 0))} with descriptor {hex(descriptor)}",
            )

        return table_address, low_bit, descriptor

    @functools.lru_cache(1025)
    def _get_valid_table(self, base_address: int) -> Optional[bytes]:
        """Extracts the translation table, validates it and returns it if it's valid."""
        table = self._context.layers.read(
            self._base_layer, base_address, self.page_size
        )
        # If the table is entirely duplicates, then mark the whole table as bad
        if table == table[: self._entry_size] * self._entry_number:
            return None

        return table

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
        mappings.This allows translation layers to provide maps of contiguous regions in one layer.

            A bit of lexical definition : "page" means "virtual page" (i.e. a chunk of virtual address space) and "page frame" means "physical page" (i.e. a chunk of physical memory).

            What this is actually doing :
                - translate a virtual offset to a physical offset
                - determine the page size the virtual offset lives in (page_size)
                - based on the position of the offset in the page, calculate how many bytes to add to get to the end of the page (chunk_size)
                - add the chunk_size to the virtual offset, so that we can point to the start of the next page

            Example (assume page size is 4096):
            -> 0xffff800000f92140 lives in page 0xfffffc0000170640 at offset 0x140, which maps to page frame 0x45c19000 at offset 0x140
                -> 4096 - 0x140 = 3776
                -> 0xffff800000f92140 + 3776 = 0xffff800000f93000
                -> we know the start of the next page is at virtual offset 0xffff800000f93000, so we can directly jump to it (no need to translate every byte in between)
            -> 0xffff800000f93000 lives in page 0xfffffc0000087040 at offset 0x0, which maps to page frame 0x421c1000 at offset 0x0
                -> 4096 - 0x0 = 4096
                -> 0xffff800000f93000 + 4096 = 0xffff800000f94000
            etc. while "length" > 0
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
                """
                Contiguous pages might not be mapped, but if we specifically ignore errors, we still want to read the n + 1 page as it might be mapped.
                """
                if not ignore_errors:
                    raise
                # We can jump more if we know where the page fault occured
                if isinstance(excp, exceptions.PagedInvalidAddressException):
                    mask = (1 << excp.invalid_bits) - 1
                else:
                    mask = (1 << self.page_shift) - 1
                length_diff = mask + 1 - (offset & mask)
                length -= length_diff
                offset += length_diff
            else:
                yield offset, chunk_size, chunk_offset, chunk_size, layer_name
                length -= chunk_size
                offset += chunk_size

    def _get_virtual_addr_range(
        self,
    ) -> Tuple[int]:
        """Returns the virtual address space range for the current context (user or kernel space)"""

        # [2], see source/arch/arm64/include/asm/memory.h#L62
        if self._virtual_addr_space == 0:
            ttb_start = 0
            ttb_size = 1 << (self._ttb_bitsize - 1)
            ttb_end = ttb_start + (ttb_size - 1)
        else:
            ttb_end = 2**64 - 1
            ttb_size = 1 << (self._ttb_bitsize - 1)
            ttb_start = ttb_end - (ttb_size - 1)

        return (ttb_start, ttb_end)

    def is_valid(self, offset: int, length: int = 1) -> bool:
        """Returns whether the address offset can be translated to a valid
        address."""
        try:
            # TODO: Consider reimplementing this, since calls to mapping can call is_valid
            return all(
                [
                    self._context.layers[layer].is_valid(mapped_offset)
                    for _, _, mapped_offset, _, layer in self.mapping(offset, length)
                ]
            )
        except exceptions.InvalidAddressException:
            return False

    def is_dirty(self, offset: int) -> bool:
        """Returns whether the page at offset is marked dirty"""
        return self._page_is_dirty(self._translate_entry(offset)[2])

    def _page_is_dirty(self, entry: int) -> bool:
        """
        Hardware management of the dirty state (only >= Armv8.1-A).

        General documentation :
         https://developer.arm.com/documentation/102376/0200/Access-Flag/Dirty-state

        Technical documentation :
         [1], see D8.4.6, page 5877 : "Hardware management of the dirty state"
         [1], see D8-16 and page 5861 : "Stage 1 attribute fields in Block and Page descriptors"

        > For the purpose of FEAT_HAFDBS, a Block descriptor or Page descriptor can be described as having one of the following states:
            • Non-writeable.
            • Writeable-clean.
            • Writeable-dirty.

        [1], see D8-41, page 5868 :
            AP[2]  | Access permission
            -------|------------------
            0      | Read/write
            1      | Read-only
        """
        if self._feat_hafdbs:
            # Dirty Bit Modifier and Access Permissions bits
            # DBM == 1 and AP == 0 -> HW dirty state
            return bool((entry & (1 << 51)) and not (entry & (1 << 7)))
        else:
            raise NotImplementedError(
                "Hardware updates to Access flag and Dirty state in translation tables are not available in the target kernel. Please try using a software based implementation of dirty bit management."
            )

    @property
    @functools.lru_cache()
    def page_shift(self) -> int:
        """Page shift for this layer, which is the page size bit length.
        - Typical values : 12, 14, 16
        """
        return self._page_size_in_bits

    @property
    @functools.lru_cache()
    def page_size(self) -> int:
        """Page size for this layer, in bytes.
        - Typical values : 4096, 16384, 65536
        """
        return self._page_size

    @property
    @functools.lru_cache()
    def page_mask(self) -> int:
        """Page mask for this layer."""
        return self.page_size - 1

    @classproperty
    @functools.lru_cache()
    def bits_per_register(cls) -> int:
        """Returns the bits_per_register to determine the range of an
        AArch64TranslationLayer."""
        return cls._bits_per_register

    @property
    @functools.lru_cache()
    def minimum_address(self) -> int:
        return self._virtual_addr_range[0]

    @property
    @functools.lru_cache()
    def maximum_address(self) -> int:
        return self._virtual_addr_range[1]

    def _read_register_field(
        self, register_field: Enum, ignore_errors: bool = False
    ) -> int:
        reg_field_path = str(register_field)
        try:
            return self._cpu_regs_mapped[reg_field_path]
        except KeyError:
            if ignore_errors:
                return None
            raise KeyError(
                f"{reg_field_path} register field wasn't provided to this layer initially."
            )

    @classmethod
    def _map_reg_values(cls, registers_values: dict) -> dict:
        """Generates a dict of dot joined AArch64 CPU registers and fields.
        Iterates over every mapped register in AArch64RegMap,
        check if a register value was provided to this layer,
        mask every field accordingly and store the result.

        Example return value :
         {'TCR_EL1.TG1': 3, 'TCR_EL1.T1SZ': 12, 'TCR_EL1.TG0': 1,
          'TCR_EL1.T0SZ': 12, 'TTBR1_EL1.ASID': 0, 'TTBR1_EL1.BADDR': 1092419584,
          'TTBR1_EL1.CnP': 0}
        """

        masked_trees = {}
        for mm_cls_name, mm_cls in inspect.getmembers(AArch64RegMap, inspect.isclass):
            if issubclass(mm_cls, Enum) and mm_cls_name in registers_values.keys():
                reg_value = registers_values[mm_cls_name]
                for field in mm_cls:
                    dot_joined = path_join(mm_cls_name, field.name)
                    high_bit, low_bit = field.value
                    masked_value = cls._mask(reg_value, high_bit, low_bit)
                    masked_trees[dot_joined] = masked_value
        return masked_trees

    def canonicalize(self, addr: int) -> int:
        """Canonicalizes an address by performing an appropiate sign extension on the higher addresses"""
        if self._bits_per_register <= self._ttb_bitsize:
            return addr & self.address_mask
        elif addr < (1 << self._ttb_bitsize - 1):
            return addr
        return self._mask(addr, self._ttb_bitsize, 0) + self._canonical_prefix

    def decanonicalize(self, addr: int) -> int:
        """Removes canonicalization to ensure an adress fits within the correct range if it has been canonicalized

        This will produce an address outside the range if the canonicalization is incorrect
        """
        if addr < (1 << self._ttb_bitsize - 1):
            return addr
        return addr ^ self._canonical_prefix

    @staticmethod
    def _mask(
        value: int, high_bit: int, low_bit: int, shift: Optional[int] = None
    ) -> int:
        """Returns the bits of a value between highbit and lowbit inclusive."""
        if shift is None:
            shift = low_bit
        high_mask = (1 << (high_bit + 1)) - 1
        low_mask = (1 << low_bit) - 1
        mask = high_mask ^ low_mask
        return (value & mask) >> shift

    @property
    def dependencies(self) -> List[str]:
        """Returns a list of the lower layer names that this layer is dependent
        upon."""
        return [self._base_layer]

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.TranslationLayerRequirement(
                name="memory_layer", optional=False
            ),
            requirements.IntRequirement(
                name="page_map_offset",
                optional=False,
                description='DTB of the target context (either "kernel space" or "user space process").',
            ),
            requirements.StringRequirement(
                name="entry_format",
                optional=False,
                description='Format and byte order of table descriptors, represented in the "struct" format.',
            ),
            requirements.BooleanRequirement(
                name="layer_debug",
                optional=True,
                description="Specify if debugging informations about the layer should be printed to user.",
                default=False,
            ),
            requirements.BooleanRequirement(
                name="translation_debug",
                optional=True,
                description="Specify if translation debugging informations should be printed to user.",
                default=False,
            ),
            requirements.IntRequirement(
                name="kernel_virtual_offset", optional=True, description="ASLR offset"
            ),
            requirements.StringRequirement(
                name="kernel_banner",
                optional=True,
                description="Kernel unique identifier, including compiler name and version, kernel version, compile time.",
            ),
            requirements.IntRequirement(
                name=AArch64RegMap.TCR_EL1.__name__,
                optional=False,
                description="TCR_EL1 register",
            ),
            requirements.IntRequirement(
                name=AArch64RegMap.TTBR1_EL1.__name__,
                optional=False,
                description="TTBR1_EL1 register",
            ),
            requirements.IntRequirement(
                name=AArch64RegMap.ID_AA64MMFR1_EL1.__name__,
                optional=True,
                description="ID_AA64MMFR1_EL1 register",
                default=None,
            ),
        ]


class LinuxAArch64Mixin(AArch64):
    def _page_is_dirty(self, entry: int) -> bool:
        """Returns whether a particular page is dirty based on its (page table) entry.
        The bit indicates that its associated block of memory
        has been modified and has not been saved to storage yet.

        The following is based on Linux software AArch64 dirty bit management.
         [2], see arch/arm64/include/asm/pgtable-prot.h#L18
         [3], see page 12-25
         https://lkml.org/lkml/2023/7/7/77 -> Linux implementation detail
        """
        sw_dirty = bool(entry & (1 << 55))
        try:
            hw_dirty = super()._page_is_dirty(entry)
            return sw_dirty or hw_dirty
        except NotImplementedError:
            return sw_dirty


class LinuxAArch64(LinuxAArch64Mixin, AArch64):
    pass


class WindowsAArch64Mixin(AArch64):
    def _page_is_dirty(self, entry: int) -> bool:
        """Returns whether a particular page is dirty based on its (page table) entry.
        The bit indicates that its associated block of memory
        has been modified and has not been saved to storage yet.

        The following is based on the Windows kernel function MiMarkPteDirty().
        Windows software DBM bit is located at offset 56, and does not account
        of hardware bit 51.
        """
        return bool((entry & (1 << 56)) and not (entry & (1 << 7)))


class WindowsAArch64(WindowsAArch64Mixin, AArch64):
    """Windows AArch64 page size is constant, and statically defined in
    CmSiGetPageSize() kernel function.

    Takes advantage of the @classproperty, as @property is dynamic
    and breaks static accesses in windows automagic.
    """

    @classproperty
    @functools.lru_cache()
    def page_shift(self) -> int:
        """Page shift for this layer, which is the page size bit length."""
        return 12

    @classproperty
    @functools.lru_cache()
    def page_size(self) -> int:
        """Page size for this layer, in bytes.
        Prefer returning the value directly, instead of adding an additional
        "_page_size" constant that could cause confusion with the parent class.
        """
        return 0x1000

    @classproperty
    @functools.lru_cache()
    def page_mask(self) -> int:
        """Page mask for this layer."""
        return self.page_size - 1


"""Avoid cluttering the layer code with static mappings."""


class AArch64RegMap:
    """
    List of static Enum's, binding fields (high bit, low bit) of AArch64 CPU registers.
    Prevents the use of hardcoded string values by unifying everything here.
    Contains only essential mappings, needed by the framework.
    """

    class TCR_EL1(Enum):
        """TCR_EL1, Translation Control Register (EL1).
        The control register for stage 1 of the EL1&0 translation regime.
         [1], see D19.2.139, page 7071
        """

        TG1 = (31, 30)
        "Granule size for the TTBR1_EL1."
        T1SZ = (21, 16)
        "The size offset of the memory region addressed by TTBR1_EL1. The region size is 2**(64-T1SZ) bytes."
        TG0 = (15, 14)
        "Granule size for the TTBR0_EL1."
        T0SZ = (5, 0)
        "The size offset of the memory region addressed by TTBR0_EL1. The region size is 2**(64-T0SZ) bytes."

    class TTBR0_EL1(Enum):
        """TTBR0_EL1, Translation Table Base Register 0 (EL1)
        Holds the base address of the translation table for the initial lookup for stage 1 of the translation of an address from the lower VA range in the EL1&0 translation regime, and other information for this translation regime.         [1], see D19.2.155, page 7152
         [1], see D19.2.152, page 7139
        """

        ASID = (63, 48)
        "An ASID for the translation table base address."
        BADDR = (47, 1)
        "Translation table base address."
        CnP = (0, 0)
        "Common not Private."

    class TTBR1_EL1(Enum):
        """TTBR1_EL1, Translation Table Base Register 1 (EL1)
        Holds the base address of the translation table for the initial lookup for stage 1 of the translation of an address from the higher VA range in the EL1&0 stage 1 translation regime, and other information for this translation regime.
         [1], see D19.2.155, page 7152
        """

        ASID = (63, 48)
        "An ASID for the translation table base address."
        BADDR = (47, 1)
        "Translation table base address."
        CnP = (0, 0)
        "Common not Private."

    class ID_AA64MMFR1_EL1(Enum):
        """ID_AA64MMFR1_EL1, AArch64 Memory Model Feature Register 1.
        [1], see D19.2.65, page 6781"""

        HAFDBS = (3, 0)
        "Hardware updates to Access flag and Dirty state in translation tables."


class AArch64RegFieldValues:
    @classmethod
    def _table_lookup(
        cls, value: int, lookup_table: dict, reverse_lookup: bool = False
    ):
        if reverse_lookup:
            lookup_table = {v: k for k, v in lookup_table.items()}
        if lookup_table.get(value, None) != None:
            return lookup_table[value]
        else:
            raise KeyError(
                f"Value {value} could not be mapped inside lookup_table : {lookup_table}"
            )

    @classmethod
    def _get_feature_HAFDBS(cls, value: int) -> bool:
        """
        Hardware updates to Access flag and Dirty state in translation tables.
         [1], see D19.2.65, page 6784
        """
        return value >= 0b10

    @classmethod
    def _get_ttbr0_el1_granule_size(cls, value: int, reverse_lookup: bool = False):
        """
        Granule size for the TTBR0_EL1.
        """
        lookup_table = {
            0b00: 4,  # 4kB
            0b01: 64,  # 64kB
            0b10: 16,  # 16kB
        }
        return cls._table_lookup(value, lookup_table, reverse_lookup)

    @classmethod
    def _get_ttbr1_el1_granule_size(
        cls, value: int, reverse_lookup: bool = False
    ) -> Optional[int]:
        """
        Granule size for the TTBR1_EL1.
        """
        lookup_table = {
            0b01: 16,  # 16kB
            0b10: 4,  # 4kB
            0b11: 64,  # 64kB
        }
        return cls._table_lookup(value, lookup_table, reverse_lookup)


def set_reg_bits(value: int, reg_field: Enum, reg_value: int = 0) -> int:
    """Sets the bits from high_bit to low_bit (inclusive) in "reg_value" to the given value.
    Allows to manipulate the bits at arbitrary positions inside a register.

    Args:
        value: The value to set in the specified bit range.
        reg_field: The register field to update, inside the register.
        reg_value: The register value to modify (default is 0).

    Returns:
        The modified integer with the specified bits set.

    Raises:
        ValueError: If the value is too large to fit in the specified bit range.
    """
    high_bit = reg_field.value[1]
    low_bit = reg_field.value[0]

    # Calculate the number of bits to set
    num_bits = low_bit - high_bit + 1

    # Calculate the maximum value that can fit in the specified number of bits
    max_value = (1 << num_bits) - 1

    # Check if the value can fit in the specified bit range
    if value > max_value:
        raise ValueError(
            f"Value {value} is too large to fit in {num_bits} bits (max value is {max_value})."
        )

    # Create a mask for the bit range
    mask = (1 << num_bits) - 1

    # Clear the bits in the range in the current value
    reg_value &= ~(mask << high_bit)

    # Set the bits with the new value
    reg_value |= (value & mask) << high_bit

    return reg_value
