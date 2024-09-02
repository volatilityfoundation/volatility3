# This file is Copyright 2022 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

from volatility3.framework import objects, constants, exceptions


class MFTEntry(objects.StructType):
    """This represents the base MFT Record"""

    def get_signature(self) -> str:
        signature = self.Signature.cast("string", max_length=4, encoding="latin-1")
        return signature


class MFTFileName(objects.StructType):
    """This represents an MFT $FILE_NAME Attribute"""

    def get_full_name(self) -> str:
        output = self.Name.cast(
            "string", encoding="utf16", max_length=self.NameLength * 2, errors="replace"
        )
        return output


class MFTAttribute(objects.StructType):
    """This represents an MFT ATTRIBUTE"""

    def get_resident_filename(self) -> str:
        # 4MB chosen as cutoff instead of 4KB to allow for recovery from format /L created file systems
        # Length as 512 as its 256*2, which is the maximum size for an entire file path, so this is even generous
        if (
            self.Attr_Header.ContentOffset > 4194304
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
        except exceptions.InvalidAddressException:
            return None

    def get_resident_filecontent(self) -> bytes:
        # smear observed in mass testing of samples
        # 4MB chosen as cutoff instead of 4KB to allow for recovery from format /L created file systems
        if (
            self.Attr_Header.ContentOffset > 4194304
            or self.Attr_Header.ContentLength > 4194304
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
        except exceptions.InvalidAddressException:
            return None
