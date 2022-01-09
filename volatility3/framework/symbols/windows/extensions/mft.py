# This file is Copyright 2022 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

import enum

from volatility3.framework import exceptions, objects, renderers
from volatility3.framework.objects import utility


class AttributeTypes(enum.Enum):
    STANDARD_INFORMATION = 0x10
    ATTRIBUTE_LIST = 0x20
    FILE_NAME = 0x30
    OBJECT_ID = 0x40
    SECURITY_DESCRIPTOR = 0x50
    VOLUME_NAME = 0x60
    VOLUME_INFORMATION = 0x70
    DATA = 0x80
    INDEX_ROOT = 0x90
    INDEX_ALLOCATION = 0xa0
    BITMAP = 0xb0
    REPARSE_POINT = 0xc0
    EA_INFORMATION = 0xd0
    EA = 0xe0
    PROPERTY_SET = 0xf0
    LOGGED_UTILITY_STREAM = 0x100
    Unknown = None

    @classmethod
    def _missing_(cls, value):
        return cls(AttributeTypes.Unknown)

class NameSpace(enum.Enum):
    POSIX = 0x0
    Win32 = 0x1
    DOS = 0x2
    Win32DOS = 0x3
    Unknown = None

    @classmethod
    def _missing_(cls, value):
        return cls(NameSpace.Unknown)


class MFTFlags(enum.Enum):
    Removed = 0x00
    File = 0x1
    Directory = 0x2
    DirInUse = 0x3
    Unknown = None

    @classmethod
    def _missing_(cls, value):
        return cls(MFTFlags.Unknown)


class PermissionFlags(enum.Enum):
    ReadOnly = 0x1
    Hidden = 0x2
    System = 0x4
    Archive = 0x20
    ArchiveHidden = 0x22
    ArchiveSystem = 0x24
    ArchiveHiddenSystem = 0x26
    Device = 0x40
    Normal = 0x80
    Temporary = 0x100
    TempArchive = 0x120
    SparseFile = 0x200
    ReparsePoint = 0x400
    Compressed = 0x800
    Offline = 0x1000
    NotIndexed = 0x2000
    Encrypted = 0x4000
    Directory = 0x10000000
    IndexView = 0x20000000
    unknown = None

    @classmethod
    def _missing_(cls, value):
        return cls(PermissionFlags.unknown)


class MFTEntry(objects.StructType):
    """This represents the base MFT Record"""

    def get_signature(self) -> str:
        signature = self.Signature.cast('string', max_length = 4, encoding = 'latin-1')
        return signature


class MFTFileName(objects.StructType):
    """This represents an MFT $FILE_NAME Attribute"""

    def get_full_name(self) -> str:
        output = self.Name.cast("string",
                                    encoding = "utf16",
                                    max_length = self.NameLength*2,
                                    errors = "replace")
        return output

    def get_file_namespace(self) -> str:
        pass
