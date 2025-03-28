# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
"""The official list of format hints that text renderers and plugins can rely
upon existing within the framework.

These hints allow a plugin to indicate how they would like data from a particular column to be represented.

Text renderers should attempt to honour all hints provided in this module where possible
"""
from typing import Type, Union

from volatility3.framework import interfaces


class Bin(int):
    """A class to indicate that the integer value should be represented as a
    binary value."""


class Hex(int):
    """A class to indicate that the integer value should be represented as a
    hexadecimal value."""


class HexBytes(bytes):
    """A class to indicate that the bytes should be display in an extended
    format showing hexadecimal and ascii printable display."""


class MultiTypeData(bytes):
    """The contents are supposed to be a string, but may contain binary data."""

    def __new__(
        cls: Type["MultiTypeData"],
        original: Union[int, bytes],
        encoding: str = "utf-16-le",
        split_nulls: bool = False,
        show_hex: bool = False,
    ) -> "MultiTypeData":
        if isinstance(original, int):
            data = str(original).encode(encoding)
        else:
            data = original
        return super().__new__(cls, data)

    def __init__(
        self,
        original: bytes,
        encoding: str = "utf-16-le",
        split_nulls: bool = False,
        show_hex: bool = False,
    ) -> None:
        self.converted_int: bool = False
        if isinstance(original, int):
            self.converted_int = True
        self.encoding = encoding
        self.split_nulls = split_nulls
        self.show_hex = show_hex
        bytes.__init__(original)

    def __eq__(self, other):
        return (
            isinstance(other, self.__class__)
            and super() == super(self.__class__, other)
            and self.converted_int == other.converted_int
            and self.encoding == other.encoding
            and self.split_nulls == other.split_nulls
            and self.show_hex == other.show_hex
        )


def BinOrAbsent(x):
    return Bin(x) if not isinstance(x, interfaces.renderers.BaseAbsentValue) else x


def HexOrAbsent(x):
    return Hex(x) if not isinstance(x, interfaces.renderers.BaseAbsentValue) else x


def HexBytesOrAbsent(x):
    return HexBytes(x) if not isinstance(x, interfaces.renderers.BaseAbsentValue) else x


def MultiTypeDataOrAbsent(x):
    return (
        MultiTypeData(x)
        if not isinstance(x, interfaces.renderers.BaseAbsentValue)
        else x
    )
