# This file is Copyright 2022 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

import logging
from typing import Dict, Iterator, List, Optional, Tuple

from volatility3.framework import constants, exceptions, interfaces, objects

vollog = logging.getLogger(__name__)


class MFTEntry(objects.StructType):
    """This represents the base MFT Record"""

    def __init__(
        self,
        context: interfaces.context.ContextInterface,
        type_name: str,
        object_info: interfaces.objects.ObjectInformation,
        size: int,
        members: Dict[str, Tuple[int, interfaces.objects.Template]],
    ) -> None:
        super().__init__(context, type_name, object_info, size, members)

        self._attrs_loaded = False
        self._attrs: List[MFTAttribute] = []

    @property
    def symbol_table_name(self) -> str:
        return self.vol.type_name.split(constants.BANG)[0]

    def get_signature(self) -> objects.String:
        signature = self.Signature.cast("string", max_length=4, encoding="latin-1")
        return signature

    @property
    def attributes(self) -> Iterator["MFTAttribute"]:
        """
        Lazily evaluate and yield attributes, caching them in an internal list
        for re-retrieval.
        """
        if not self._attrs_loaded:
            self._attrs = list(self._attributes())
            self._attrs_loaded = True

        yield from self._attrs

    def longest_filename(self) -> Optional[objects.String]:
        names = [name.get_full_name() for name in self.filename_entries()]
        if not names:
            return None

        return max(names, key=lambda x: len(str(x)))

    def _attributes(self) -> Iterator["MFTAttribute"]:
        # We will update this on each pass in the next loop and use it as the new offset.
        attr_base_offset = self.FirstAttrOffset
        attribute_object_type_name = (
            self.symbol_table_name + constants.BANG + "ATTRIBUTE"
        )

        attr: MFTAttribute = self._context.object(
            attribute_object_type_name,
            offset=self.vol.offset + attr_base_offset,
            layer_name=self.vol.layer_name,
        )

        # There is no field that has a count of Attributes
        # Keep Attempting to read attributes until we get an invalid attr_header.AttrType
        try:
            while attr.Attr_Header.AttrType.is_valid_choice:
                yield attr

                # If there's no advancement the loop will never end, so break it now
                if attr.Attr_Header.Length == 0:
                    break

                # Update the base offset to point to the next attribute
                attr_base_offset += attr.Attr_Header.Length
                # Get the next attribute
                attr: MFTAttribute = self._context.object(
                    attribute_object_type_name,
                    offset=self.vol.offset + attr_base_offset,
                    layer_name=self.vol.layer_name,
                )
        except exceptions.InvalidAddressException as e:
            vollog.debug(
                f"Failed to read attribute at {attr.vol.offset:#x}: {e.__class__.__name__}"
            )
            return

    def standard_information_entries(
        self,
    ) -> Iterator[objects.StructType]:
        """
        Yields a STANDARD_INFORMATION struct for each of the
        STANDARD_INFORMATION attributes in this MFT record (although there
        should only be one per record).
        """
        for attr in self.attributes:
            attr_type = attr.Attr_Header.AttrType.lookup()
            if attr_type != "STANDARD_INFORMATION":
                continue

            si_object = (
                self.symbol_table_name + constants.BANG + "STANDARD_INFORMATION_ENTRY"
            )

            yield attr.Attr_Data.cast(si_object)

    def filename_entries(self) -> Iterator["MFTFileName"]:
        """
        Yields an MFT Filename for each of the FILE_NAME attributes contained
        in this MFT record. There are often two - one for the long filename,
        and the other with the DOS 8.3 short name.
        """
        for attr in self.attributes:
            try:
                attr_type = attr.Attr_Header.AttrType.lookup()
                if attr_type != "FILE_NAME":
                    continue

                fn_object = self.symbol_table_name + constants.BANG + "FILE_NAME_ENTRY"
                attr_data = attr.Attr_Data.cast(fn_object)
            except exceptions.InvalidAddressException as e:
                vollog.debug(
                    f"Failed to read attr at {attr.vol.offset:#x}: {e.__class__.__name__}"
                )
                continue
            yield attr_data

    def _data_attributes(self):
        for attr in self.attributes:
            if not (
                attr.Attr_Header.AttrType.lookup() == "DATA"
                and attr.Attr_Header.NonResidentFlag == 0
            ):
                continue

            yield attr

    def resident_data_attributes(self) -> Iterator["MFTAttribute"]:
        """
        Yields all MFT attributes that contain resident data for the primary
        stream.
        """
        for attr in self._data_attributes():
            if attr.Attr_Header.NameLength == 0:
                yield attr

    def alternate_data_streams(self) -> Iterator["MFTAttribute"]:
        """
        Yields all MFT attributes that contain alternate data streams (ADS).
        """
        for attr in self._data_attributes():
            if attr.Attr_Header.NameLength != 0:
                yield attr


class MFTFileName(objects.StructType):
    """This represents an MFT $FILE_NAME Attribute"""

    def get_full_name(self) -> objects.String:
        """
        Returns the UTF-16 decoded filename.
        """
        output = self.Name.cast(
            "string", encoding="utf16", max_length=self.NameLength * 2, errors="replace"
        )
        return output


class MFTAttribute(objects.StructType):
    """This represents an MFT ATTRIBUTE"""

    def get_resident_filename(self) -> Optional[objects.String]:
        """
        Returns the resident filename (typically for an Alternate Data Stream (ADS)).
        """
        # 4MB chosen as cutoff instead of 4KB to allow for recovery from format /L created file systems
        # Length as 512 as its 256*2, which is the maximum size for an entire file path, so this is even generous
        if (
            self.Attr_Header.ContentOffset > 0x400000
            or self.Attr_Header.NameLength > 512
        ):
            return None

        # To get the resident name, we jump to relative name offset and read name length * 2 bytes of data
        try:
            name = self._context.object(
                self.vol.type_name.split(constants.BANG)[0] + constants.BANG + "string",
                layer_name=self.vol.layer_name,
                offset=self.vol.offset + self.Attr_Header.NameOffset,
                max_length=self.Attr_Header.NameLength * 2,
                errors="replace",
                encoding="utf16",
            )
            return name
        except exceptions.InvalidAddressException as e:
            vollog.debug(
                f"Failed to get resident file content due to {e.__class__.__name__}"
            )
            return None

    def get_resident_filecontent(self) -> Optional[objects.Bytes]:
        """
        Returns the file content that is resident within this MFT attribute,
        for either the primary or an alternate data stream.
        """
        # smear observed in mass testing of samples
        # 4MB chosen as cutoff instead of 4KB to allow for recovery from format /L created file systems
        if (
            self.Attr_Header.ContentOffset > 0x400000
            or self.Attr_Header.ContentLength > 0x400000
        ):
            return None

        # To get the resident content, we jump to relative content offset and read name length * 2 bytes of data
        try:
            bytesobj = self._context.object(
                self.vol.type_name.split(constants.BANG)[0] + constants.BANG + "bytes",
                layer_name=self.vol.layer_name,
                offset=self.vol.offset + self.Attr_Header.ContentOffset,
                native_layer_name=self.vol.native_layer_name,
                length=self.Attr_Header.ContentLength,
            )
            return bytesobj
        except exceptions.InvalidAddressException as e:
            vollog.debug(
                f"Failed to get resident file content due to {e.__class__.__name__}"
            )
            return None
