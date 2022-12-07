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
