"""The official list of format hints that text renderers and plugins can rely upon existing within the framework

These hints allow a plugin to indicate how they'd like a particular column's data to be represented.

Text renderers should attempt to honour all hints provided in this module where possible
"""


class Hex(int):
    """A class to indicate that the integer value should be represented as a hexidecimal value"""


class HexBytes(int):
    """A class to indicate that the bytes should be display in an extended format showing hexadecimal and ascii printable display"""
