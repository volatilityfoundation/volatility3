# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl_v1.0
#
"""The official list of format hints that text renderers and plugins can rely upon existing within the framework

These hints allow a plugin to indicate how they would like data from a particular column to be represented.

Text renderers should attempt to honour all hints provided in this module where possible
"""


class Bin(int):
    """A class to indicate that the integer value should be represented as a binary value"""


class Hex(int):
    """A class to indicate that the integer value should be represented as a hexidecimal value"""


class HexBytes(bytes):
    """A class to indicate that the bytes should be display in an extended format showing hexadecimal and ascii printable display"""
