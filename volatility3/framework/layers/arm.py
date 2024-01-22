# This file is Copyright 2024 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

import logging
import functools
import collections
from typing import Optional, Dict, Any, List, Iterable, Tuple

from volatility3 import classproperty
from volatility3.framework import interfaces, exceptions
from volatility3.framework.configuration import requirements
from volatility3.framework.layers import linear

vollog = logging.getLogger(__name__)

"""
Webography :
 [1] Arm, "Arm Architecture Reference Manual for A-profile architecture, DDI 0487J.a (ID042523)", https://developer.arm.com/documentation/ddi0487/ja/?lang=en
 [2] Linux, Linux Kernel source code, v6.7

Glossary :
 TTB : Translation Table Base
 TCR : Translation Control Register
 EL : Exception Level (0:Application,1:Kernel,2:Hypervisor,3:Secure Monitor)
 Granule : Translation granule (smallest block of memory that can be described)
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
        self._layer_debug = self.config.get("layer_debug", False)
        self._translation_debug = self.config.get("translation_debug", False)
        self._base_layer = self.config["memory_layer"]
        # self._swap_layers = []  # TODO
        self._page_map_offset = self.config["page_map_offset"]
        self._tcr_el1_tnsz = self.config["tcr_el1_tnsz"]
        self._page_size = self.config["page_size"]

        # Context : TTB0 (user) or TTB1 (kernel)
        self._virtual_addr_space = (
            self._page_map_offset == self.config["page_map_offset_kernel"]
        )
        self._ttbs_tnsz = [self._tcr_el1_tnsz, self._tcr_el1_tnsz]

        # [1], see D8.1.9, page 5818
        self._ttbs_bitsizes = [64 - self._ttbs_tnsz[0], 64 - self._ttbs_tnsz[1]]
        self._ttbs_granules = [self._page_size, self._page_size]

        self._is_52bits = [
            True if self._ttbs_tnsz[ttb] < 16 else False for ttb in range(2)
        ]

        # [1], see D8.2.7 to D8.2.9, starting at page 5828
        self._granules_indexes = {
            4: [(51, 48), (47, 39), (38, 30), (29, 21), (20, 12)],
            16: [(51, 47), (46, 36), (35, 25), (24, 14)],
            64: [(51, 42), (41, 29), (28, 16)],
        }
        self._ttb_lookups_descriptors = self._determine_ttbs_lookup_descriptors()

        # [1], see D8.3, page 5852
        self._descriptors_bits = [
            (
                49
                if self._ttbs_granules[ttb] in [4, 16] and self._is_52bits[ttb]
                else 47,
                self._ttb_lookups_descriptors[ttb][-1][1],
            )
            for ttb in range(2)
        ]

        self._virtual_addr_range = self._get_virtual_addr_ranges()[
            self._virtual_addr_space
        ]

        self._context_maxvirtaddr = self._ttbs_bitsizes[self._virtual_addr_space]
        self._canonical_prefix = self._mask(
            (1 << self._bits_per_register) - 1,
            self._bits_per_register,
            self._context_maxvirtaddr,
        )
        if self._layer_debug:
            self._print_layer_debug_informations()

        if AARCH64_DEBUGGING:
            vollog.debug(f"Base layer : {self._base_layer}")
            vollog.debug(
                f"Virtual address space : {'kernel' if self._virtual_addr_space else 'user'}"
            )
            vollog.debug(
                f"Virtual addresses spaces ranges : {[tuple([hex(y) for y in x]) for x in self._get_virtual_addr_ranges()]}"
            )
            vollog.debug(f"Pages sizes : {self._ttbs_granules}")
            vollog.debug(f"TnSZ values : {self._ttbs_bitsizes}")
            vollog.debug(f"Page map offset : {hex(self._page_map_offset)}")
            vollog.debug(f"Descriptors mappings : {self._ttb_lookups_descriptors}")

    def _determine_ttbs_lookup_descriptors(self) -> List[int]:
        """Returns the bits to extract from a translation address (highs and lows)"""
        ttb_lookups_descriptors = []

        for ttb, ttb_granule in enumerate(self._ttbs_granules):
            va_bit_size = self._ttbs_bitsizes[ttb]
            indexes = [
                index
                for index in self._granules_indexes[ttb_granule]
                if va_bit_size > index[1]
            ]
            indexes[0] = (va_bit_size - 1, indexes[0][1])
            ttb_lookups_descriptors.append(indexes)

        return ttb_lookups_descriptors

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

        # [1], see D8.2.4, page 5824
        ttb_selector = self._mask(virtual_offset, 55, 55)

        # Check if requested address belongs to the context virtual memory space
        if ttb_selector != self._virtual_addr_space:
            raise exceptions.InvalidAddressException(
                layer_name=self.name,
                invalid_address=virtual_offset,
            )

        lookup_descriptor = self._ttb_lookups_descriptors[ttb_selector]
        table_address = self._page_map_offset
        level = 0
        max_level = len(lookup_descriptor) - 1

        for high_bit, low_bit in lookup_descriptor:
            index = self._mask(virtual_offset, high_bit, low_bit)

            # TODO: Adapt endianness ?
            descriptor = int.from_bytes(
                base_layer.read(
                    table_address + (index * self._register_size), self._register_size
                ),
                byteorder="little",
            )
            ta_51_x = None

            # [1], see D8.3, page 5852
            if self._is_52bits[ttb_selector]:
                if self._ttbs_granules[ttb_selector] in [4, 16]:
                    ta_51_x_bits = (9, 8)
                elif self._ttbs_granules[ttb_selector] == 64:
                    ta_51_x_bits = (15, 12)

                ta_51_x = self._mask(
                    descriptor,
                    ta_51_x_bits[0],
                    ta_51_x_bits[1],
                )
                ta_51_x = ta_51_x << (52 - ta_51_x.bit_length())

            # [1], see D8.3, page 5852
            descriptor_type = self._mask(descriptor, 1, 0)
            # Table descriptor
            if level < max_level and descriptor_type == 0b11:
                table_address = (
                    self._mask(
                        descriptor,
                        self._descriptors_bits[ttb_selector][0],
                        self._descriptors_bits[ttb_selector][1],
                    )
                    << self._descriptors_bits[ttb_selector][1]
                )
                table_address = ta_51_x | table_address if ta_51_x else table_address
            # Block descriptor
            elif level < max_level and descriptor_type == 0b01:
                table_address = (
                    self._mask(
                        descriptor,
                        self._descriptors_bits[ttb_selector][0],
                        low_bit,
                    )
                    << low_bit
                )
                table_address = ta_51_x | table_address if ta_51_x else table_address
                break
            # Page descriptor
            elif level == max_level and descriptor_type == 0b11:
                table_address = (
                    self._mask(
                        descriptor,
                        self._descriptors_bits[ttb_selector][0],
                        self._descriptors_bits[ttb_selector][1],
                    )
                    << self._descriptors_bits[ttb_selector][1]
                )
                table_address = ta_51_x | table_address if ta_51_x else table_address
                break
            # Invalid descriptor || Reserved descriptor (level 3)
            else:
                raise exceptions.PagedInvalidAddressException(
                    layer_name=self.name,
                    invalid_address=virtual_offset,
                    invalid_bits=low_bit,
                    entry=descriptor,
                )
            level += 1

        if self._translation_debug:
            vollog.debug(
                f"Virtual {hex(virtual_offset)} lives in page frame {hex(table_address)} at offset {hex(self._mask(virtual_offset, low_bit-1, 0))}",
            )

        return table_address, low_bit, descriptor

    def mapping(
        self, offset: int, length: int, ignore_errors: bool = False
    ) -> Iterable[Tuple[int, int, int, int, str]]:
        """Returns a sorted iterable of (offset, sublength, mapped_offset, mapped_length, layer)
        mappings.

        This allows translation layers to provide maps of contiguous
        regions in one layer
        """
        stashed_offset = (
            stashed_mapped_offset
        ) = stashed_size = stashed_mapped_size = stashed_map_layer = None
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
            """
            A bit of lexical definition : "page" means "virtual page" (i.e. a chunk of virtual address space) and "page frame" means "physical page" (i.e. a chunk of physical memory).

            What this is actually doing :
                - translate a virtual offset to a physical offset
                - determine the page size the virtual offset lives in (page_size)
                - based on the position of the offset in the page, calculate how many bytes to add to get to the end of the page (chunk_size)
                - add the chunk_size to the virtual offset, so that we can point to the start of the next page frame

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
                # We can jump more if we know where the page fault failed
                if isinstance(excp, exceptions.PagedInvalidAddressException):
                    mask = (1 << excp.invalid_bits) - 1
                else:
                    mask = (
                        1
                        << (
                            self._ttbs_granules[self._virtual_addr_space].bit_length()
                            - 1
                        )
                    ) - 1
                length_diff = mask + 1 - (offset & mask)
                length -= length_diff
                offset += length_diff
            else:
                yield offset, chunk_size, chunk_offset, chunk_size, layer_name
                length -= chunk_size
                offset += chunk_size

    def _get_virtual_addr_ranges(
        self,
    ) -> List[Tuple[int]]:
        """Returns the virtual address space ranges as [(LOW_START, LOW_END), (HIGH_START, HIGH_END)]"""
        # [2], see source/arch/arm64/include/asm/memory.h#L62
        ttb0_start = 0
        ttb0_size = 1 << (self._ttbs_bitsizes[0] - 1)
        ttb0_end = ttb0_start + (ttb0_size - 1)
        ttb1_end = 2**64 - 1
        ttb1_size = 1 << (self._ttbs_bitsizes[1] - 1)
        ttb1_start = ttb1_end - (ttb1_size - 1)

        return [(ttb0_start, ttb0_end), (ttb1_start, ttb1_end)]

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

    @staticmethod
    def _page_is_dirty(entry: int) -> bool:
        """Returns whether a particular page is dirty based on its entry."""
        # [2], see arch/arm64/include/asm/pgtable-prot.h#L18
        return bool(entry & (1 << 55))

    @classproperty
    @functools.lru_cache()
    def minimum_address(cls) -> int:
        return 0

    @classproperty
    @functools.lru_cache()
    def maximum_address(cls) -> int:
        return (1 << cls._maxvirtaddr) - 1

    def __canonicalize(self, addr: int) -> int:
        """Canonicalizes an address by performing an appropiate sign extension on the higher addresses"""
        if self._bits_per_register <= self._context_maxvirtaddr:
            return addr & self.address_mask
        elif addr < (1 << self._context_maxvirtaddr - 1):
            return addr
        return self._mask(addr, self._context_maxvirtaddr, 0) + self._canonical_prefix

    def __decanonicalize(self, addr: int) -> int:
        """Removes canonicalization to ensure an adress fits within the correct range if it has been canonicalized

        This will produce an address outside the range if the canonicalization is incorrect
        """
        if addr < (1 << self._context_maxvirtaddr - 1):
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
            requirements.IntRequirement(
                name="page_map_offset_kernel",
                optional=False,
                description="DTB of the kernel space, it is primarily used to determine the target context of the layer (page_map_offset == page_map_offset_kernel). Conveniently calculated by LinuxStacker.",
            ),
            requirements.IntRequirement(
                name="tcr_el1_t0sz",
                optional=False,
                description="The size offset of the memory region addressed by TTBR0_EL1. Conveniently calculated by LinuxStacker.",
            ),
            requirements.IntRequirement(
                name="tcr_el1_t1sz",
                optional=False,
                description="The size offset of the memory region addressed by TTBR1_EL1. Conveniently calculated by LinuxStacker.",
            ),
            requirements.IntRequirement(
                name="page_size_user_space",
                optional=False,
                description="Page size used by the user address space. Conveniently calculated by LinuxStacker.",
            ),
            requirements.IntRequirement(
                name="page_size_kernel_space",
                optional=False,
                description="Page size used by the kernel address space. Conveniently calculated by LinuxStacker.",
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
                description="Linux banner (/proc/version)",
            ),
        ]
