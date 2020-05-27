# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
"""The official list of format hints that text renderers and plugins can rely
upon existing within the framework.

These hints allow a plugin to indicate how they would like data from a particular column to be represented.

Text renderers should attempt to honour all hints provided in this module where possible
"""


class Bin(int):
    """A class to indicate that the integer value should be represented as a
    binary value."""


class Hex(int):
    """A class to indicate that the integer value should be represented as a
    hexidecimal value."""


class HexBytes(bytes):
    """A class to indicate that the bytes should be display in an extended
    format showing hexadecimal and ascii printable display."""


class StrLike(bytes):
    """The contents are supposed to be a string, but may contain binary data."""

    def __new__(cls, original, encoding: str = 'utf-16-le'):
        return super().__new__(cls, original)

    def __init__(self, original: bytes, encoding: str = 'utf-16-le'):
        self.original = original
        self._encoding = encoding
        bytes.__init__(original)

    def __str__(self):
        return str(self.original, encoding = self._encoding, errors = 'replace').split("\x00")[0]
