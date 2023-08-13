import contextlib
import functools
import logging
import struct
from typing import Dict, List, Optional, Tuple, Union

from volatility3.plugins.windows.poolscanner import PoolConstraint

from volatility3.framework import (
    constants,
    exceptions,
    interfaces,
    objects,
    renderers,
    symbols,
)
from volatility3.framework.renderers import conversion

vollog = logging.getLogger(__name__)


class POOL_HEADER(objects.StructType):
    """A kernel pool allocation header.

    Exists at the base of the allocation and provides a tag that we can
    scan for.
    """

    def get_object(
        self,
        constraint: PoolConstraint,
        use_top_down: bool,
        kernel_symbol_table: Optional[str] = None,
        native_layer_name: Optional[str] = None,
    ) -> Optional[interfaces.objects.ObjectInterface]:
        """Carve an object or data structure from a kernel pool allocation

        Args:
            constraint: a PoolConstraint object used to get the pool allocation header object
            use_top_down: for delineating how a windows version finds the size of the object body
            kernel_symbol_table: in case objects of a different symbol table are scanned for
            native_layer_name: the name of the layer where the data originally lived

        Returns:
            An object as found from a POOL_HEADER
        """

        type_name = constraint.type_name
        executive = constraint.object_type is not None

        symbol_table_name = self.vol.type_name.split(constants.BANG)[0]
        if constants.BANG in type_name:
            symbol_table_name, type_name = type_name.split(constants.BANG)[0:2]

        # when checking for symbols from a table other than nt_symbols grab _OBJECT_HEADER from the kernel
        # because symbol_table_name will be different from kernel_symbol_table.
        if kernel_symbol_table:
            object_header_type = self._context.symbol_space.get_type(
                kernel_symbol_table + constants.BANG + "_OBJECT_HEADER"
            )
        else:
            # otherwise symbol_table_name *is* the kernel symbol table, so just use that.
            object_header_type = self._context.symbol_space.get_type(
                symbol_table_name + constants.BANG + "_OBJECT_HEADER"
            )

        pool_header_size = self.vol.size

        # if there is no object type, then just instantiate a structure
        if not executive:
            mem_object = self._context.object(
                symbol_table_name + constants.BANG + type_name,
                layer_name=self.vol.layer_name,
                offset=self.vol.offset + pool_header_size,
                native_layer_name=native_layer_name,
            )
            yield mem_object

        # otherwise we have an executive object in the pool
        else:
            if symbols.symbol_table_is_64bit(self._context, symbol_table_name):
                alignment = 16
            else:
                alignment = 8

            # use the top down approach for windows 8 and later
            if use_top_down:
                body_offset = object_header_type.relative_child_offset("Body")
                infomask_offset = object_header_type.relative_child_offset("InfoMask")
                pointercount_offset = object_header_type.relative_child_offset(
                    "PointerCount"
                )
                pointercount_size = object_header_type.members["PointerCount"][1].size
                (
                    optional_headers,
                    lengths_of_optional_headers,
                ) = self._calculate_optional_header_lengths(
                    self._context, symbol_table_name
                )
                padding_available = (
                    None
                    if "PADDING_INFO" not in optional_headers
                    else optional_headers.index("PADDING_INFO")
                )
                max_optional_headers_length = sum(lengths_of_optional_headers)

                # define the starting and ending bounds for the scan
                start_offset = self.vol.offset + pool_header_size
                addr_limit = min(
                    max_optional_headers_length, self.BlockSize * alignment
                )

                # A single read is better than lots of little one-byte reads.
                # We're ok padding this, because the byte we'd check would be 0 which would only be valid if there
                # were no optional headers in the first place (ie, if we read too much for headers that don't exist,
                # but the bit we could read were valid)
                infomask_data = self._context.layers[self.vol.layer_name].read(
                    start_offset, addr_limit + infomask_offset, pad=True
                )

                # Addr stores the offset to the potential start of the OBJECT_HEADER from just after the POOL_HEADER
                # It will always be aligned to a particular alignment
                for addr in range(0, addr_limit, alignment):
                    infomask_value = infomask_data[addr + infomask_offset]
                    pointercount_value = int.from_bytes(
                        infomask_data[
                            addr
                            + pointercount_offset : addr
                            + pointercount_offset
                            + pointercount_size
                        ],
                        byteorder="little",
                        signed=True,
                    )
                    if not 0x1000000 > pointercount_value >= 0:
                        continue

                    padding_present = False
                    optional_headers_length = 0
                    for i in range(len(lengths_of_optional_headers)):
                        if infomask_value & (1 << i):
                            optional_headers_length += lengths_of_optional_headers[i]
                            if i == padding_available:
                                padding_present = True

                    # PADDING_INFO is a special case (4 bytes that contain the total padding length)
                    padding_length = 0
                    if padding_present:
                        # Read the four bytes from just before the next optional_headers_length minus the padding_info size
                        #
                        #  ---------------
                        #  POOL_HEADER
                        #  ---------------
                        #
                        #  start of PADDING_INFO
                        #  ---------------
                        #  End of other optional headers
                        #  ---------------
                        #  OBJECT_HEADER
                        #  ---------------
                        if addr - optional_headers_length < 0:
                            continue
                        (padding_length,) = struct.unpack(
                            "<I",
                            infomask_data[
                                addr
                                - optional_headers_length : addr
                                - optional_headers_length
                                + 4
                            ],
                        )
                        padding_length -= lengths_of_optional_headers[
                            padding_available or 0
                        ]

                    # Certain versions of windows have PADDING_INFO lengths that are too long
                    # So we now check that the padding length is at a minimum the right length
                    # and that it doesn't go beyond the entirety of the data
                    if addr - optional_headers_length >= padding_length > addr:
                        continue

                    with contextlib.suppress(
                        TypeError, exceptions.InvalidAddressException
                    ):
                        mem_object = self._context.object(
                            symbol_table_name + constants.BANG + type_name,
                            layer_name=self.vol.layer_name,
                            offset=addr + body_offset + start_offset,
                            native_layer_name=native_layer_name,
                        )

                        if mem_object.is_valid():
                            yield mem_object

            # use the bottom up approach for windows 7 and earlier
            else:
                type_size = self._context.symbol_space.get_type(
                    symbol_table_name + constants.BANG + type_name
                ).size
                if constraint.additional_structures:
                    for additional_structure in constraint.additional_structures:
                        type_size += self._context.symbol_space.get_type(
                            symbol_table_name + constants.BANG + additional_structure
                        ).size

                rounded_size = conversion.round(type_size, alignment, up=True)

                mem_object = self._context.object(
                    symbol_table_name + constants.BANG + type_name,
                    layer_name=self.vol.layer_name,
                    offset=self.vol.offset + self.BlockSize * alignment - rounded_size,
                    native_layer_name=native_layer_name,
                )

                with contextlib.suppress(TypeError, exceptions.InvalidAddressException):
                    if mem_object.is_valid():
                        yield mem_object

    @classmethod
    @functools.lru_cache()
    def _calculate_optional_header_lengths(
        cls, context: interfaces.context.ContextInterface, symbol_table_name: str
    ) -> Tuple[List[str], List[int]]:
        headers = []
        sizes = []
        for header in [
            "CREATOR_INFO",
            "NAME_INFO",
            "HANDLE_INFO",
            "QUOTA_INFO",
            "PROCESS_INFO",
            "AUDIT_INFO",
            "EXTENDED_INFO",
            "HANDLE_REVOCATION_INFO",
            "PADDING_INFO",
        ]:
            with contextlib.suppress(AttributeError, exceptions.SymbolError):
                type_name = (
                    f"{symbol_table_name}{constants.BANG}_OBJECT_HEADER_{header}"
                )
                header_type = context.symbol_space.get_type(type_name)
                headers.append(header)
                sizes.append(header_type.size)
                # Some of these may not exist, for example:
                #   if build < 9200: PADDING_INFO else: AUDIT_INFO
                #   if build == 10586: HANDLE_REVOCATION_INFO else EXTENDED_INFO
                # based on what's present and what's not, this list should be the right order and the right length
        return headers, sizes

    def is_free_pool(self):
        return self.PoolType == 0

    def is_paged_pool(self):
        return self.PoolType % 2 == 0 and self.PoolType > 0

    def is_nonpaged_pool(self):
        return self.PoolType % 2 == 1


class POOL_HEADER_VISTA(POOL_HEADER):
    """A kernel pool allocation header, updated for Vista and later.

    Exists at the base of the allocation and provides a tag that we can
    scan for.
    """

    def is_paged_pool(self):
        return self.PoolType % 2 == 1

    def is_nonpaged_pool(self):
        return self.PoolType % 2 == 0 and self.PoolType > 0


class POOL_TRACKER_BIG_PAGES(objects.StructType):
    """A kernel big page pool tracker."""

    pool_type_lookup: Dict[str, str] = {}

    def _generate_pool_type_lookup(self):
        # Enumeration._generate_inverse_choices() raises ValueError because multiple enum names map to the same
        # value in the kernel _POOL_TYPE so create a custom mapping here and take the first match
        symbol_table_name = self.vol.type_name.split(constants.BANG)[0]
        pool_type_enum = self._context.symbol_space.get_enumeration(
            symbol_table_name + constants.BANG + "_POOL_TYPE"
        )
        for k, v in pool_type_enum.choices.items():
            if v not in self.pool_type_lookup:
                self.pool_type_lookup[v] = k

    def is_valid(self) -> bool:
        return self.Key > 0

    def is_free(self) -> bool:
        """Returns if the allocation is freed (True) or in-use (False)"""
        return self.Va & 1 == 1

    def get_key(self) -> str:
        """Returns the Key value as a 4 character string"""
        tag_bytes = objects.convert_value_to_data(
            self.Key, int, objects.DataFormatInfo(4, "little", False)
        )
        return "".join([chr(x) if 32 < x < 127 else "" for x in tag_bytes])

    def get_pool_type(self) -> Union[str, interfaces.renderers.BaseAbsentValue]:
        """Returns the enum name for the PoolType value on applicable systems"""
        # Not applicable until Vista
        if hasattr(self, "PoolType"):
            if not self.pool_type_lookup:
                self._generate_pool_type_lookup()
            return self.pool_type_lookup.get(
                self.PoolType, f"Unknown choice {self.PoolType}"
            )
        else:
            return renderers.NotApplicableValue()

    def get_number_of_bytes(self) -> Union[int, interfaces.renderers.BaseAbsentValue]:
        """Returns the NumberOfBytes value on applicable systems"""
        # Not applicable until Vista
        try:
            return self.NumberOfBytes
        except AttributeError:
            return renderers.NotApplicableValue()


class ExecutiveObject(interfaces.objects.ObjectInterface):
    """This is used as a "mixin" that provides all kernel executive objects
    with a means of finding their own object header."""

    def get_object_header(self) -> "OBJECT_HEADER":
        if constants.BANG not in self.vol.type_name:
            raise ValueError(
                f"Invalid symbol table name syntax (no {constants.BANG} found)"
            )
        symbol_table_name = self.vol.type_name.split(constants.BANG)[0]
        body_offset = self._context.symbol_space.get_type(
            symbol_table_name + constants.BANG + "_OBJECT_HEADER"
        ).relative_child_offset("Body")
        return self._context.object(
            symbol_table_name + constants.BANG + "_OBJECT_HEADER",
            layer_name=self.vol.layer_name,
            offset=self.vol.offset - body_offset,
            native_layer_name=self.vol.native_layer_name,
        )


class OBJECT_HEADER(objects.StructType):
    """A class for the headers for executive kernel objects, which contains
    quota information, ownership details, naming data, and ACLs."""

    def is_valid(self) -> bool:
        """Determine if the object is valid."""

        # if self.InfoMask > 0x48:
        #    return False

        try:
            if self.PointerCount > 0x1000000 or self.PointerCount < 0:
                return False
        except exceptions.InvalidAddressException:
            return False

        return True

    def get_object_type(
        self, type_map: Dict[int, str], cookie: int = None
    ) -> Optional[str]:
        """Across all Windows versions, the _OBJECT_HEADER embeds details on
        the type of object (i.e. process, file) but the way its embedded
        differs between versions.

        This API abstracts away those details.
        """

        if self.vol.get("object_header_object_type", None) is not None:
            return self.vol.object_header_object_type

        try:
            # vista and earlier have a Type member
            self._vol["object_header_object_type"] = self.Type.Name.String
        except AttributeError:
            # windows 7 and later have a TypeIndex, but windows 10
            # further encodes the index value with nt1!ObHeaderCookie
            try:
                type_index = ((self.vol.offset >> 8) ^ cookie ^ self.TypeIndex) & 0xFF
            except (AttributeError, TypeError):
                type_index = self.TypeIndex

            self._vol["object_header_object_type"] = type_map.get(type_index)
        return self.vol.object_header_object_type

    @property
    def NameInfo(self) -> interfaces.objects.ObjectInterface:
        if constants.BANG not in self.vol.type_name:
            raise ValueError(
                f"Invalid symbol table name syntax (no {constants.BANG} found)"
            )

        symbol_table_name = self.vol.type_name.split(constants.BANG)[0]

        if symbol_table_name in self._context.modules:
            ntkrnlmp = self._context.modules[symbol_table_name]
        else:
            layer = self._context.layers[self.vol.native_layer_name]
            kvo = layer.config.get("kernel_virtual_offset", None)

            if kvo is None:
                raise AttributeError(
                    f"Could not find kernel_virtual_offset for layer: {self.vol.layer_name}"
                )

            # We know this symbol table name can't exist because we checked for it earlier
            ntkrnlmp = self._context.module(
                symbol_table_name, layer_name=self.vol.layer_name, offset=kvo
            )

        try:
            header_offset = self.NameInfoOffset
        except AttributeError:
            # http://codemachine.com/article_objectheader.html (Windows 7 and later)
            name_info_bit = 0x2

            address = ntkrnlmp.get_symbol("ObpInfoMaskToOffset").address
            calculated_index = self.InfoMask & (name_info_bit | (name_info_bit - 1))

            header_offset = ntkrnlmp.object(
                "unsigned char",
                layer_name=self.vol.native_layer_name,
                offset=address + calculated_index,
            )

        if header_offset == 0:
            raise ValueError(
                "Could not find _OBJECT_HEADER_NAME_INFO for object at {} of layer {}".format(
                    self.vol.offset, self.vol.layer_name
                )
            )

        header = ntkrnlmp.object(
            "_OBJECT_HEADER_NAME_INFO",
            layer_name=self.vol.layer_name,
            offset=self.vol.offset - header_offset,
            native_layer_name=self.vol.native_layer_name,
            absolute=True,
        )
        return header
