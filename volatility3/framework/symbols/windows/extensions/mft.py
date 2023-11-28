# This file is Copyright 2022 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

from volatility3.framework import objects


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
        # To get the resident name, we jump to relative name offset and read name length * 2 bytes of data
        layer = self._context.layers[self.vol.layer_name]
        attr_name_offset = self.vol.offset + self.Attr_Header.NameOffset
       
        return self._context.layers[layer.name].read(
            attr_name_offset, self.Attr_Header.NameLength*2 , pad=True
        ).decode('utf-16')
    
    def get_resident_filecontent(self) -> bytes:
        # To get the resident content, we jump to relative content offset and read name length * 2 bytes of data
        layer = self._context.layers[self.vol.layer_name]
        attr_content_offset = self.vol.offset + self.Attr_Header.ContentOffset
        
        return self._context.layers[layer.name].read(
                attr_content_offset, self.Attr_Header.ContentLength , pad=True
        )
