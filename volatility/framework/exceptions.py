"""A list of potential exceptions that volatility can throw.

These include exceptions that can be thrown on errors by the symbol space or symbol tables, and by layers when
an address is invalid.  The :class:`PagedInvalidAddressException` contains information about the size of the invalid
page.
"""


class VolatilityException(Exception):
    """Class to allow filtering of all VolatilityExceptions"""


class PluginRequirementException(VolatilityException):
    """Class to allow plugins to indicate that a requirement has not been fulfilled"""


class SymbolError(VolatilityException):
    """Thrown when a symbol lookup has failed"""


class InvalidAddressException(VolatilityException):
    """Thrown when an address is not valid in the space it was requested"""

    def __init__(self, layer_name, invalid_address, *args):
        super().__init__(layer_name, invalid_address, *args)
        self.invalid_address = invalid_address
        self.layer_name = layer_name


class PagedInvalidAddressException(InvalidAddressException):
    """Thrown when an address is not valid in the paged space in which it was request

    Includes the invalid address and the number of bits of the address that are invalid
    """

    def __init__(self,
                 layer_name: str,
                 invalid_address: int,
                 invalid_bits: int,
                 entry: int,
                 *args) -> None:
        super().__init__(layer_name, invalid_address, *args)
        self.invalid_bits = invalid_bits
        self.entry = entry


class InvalidDataException(VolatilityException):
    """Thrown when an object contains some data known to be invalid for that structure"""

    def __init__(self, invalid_object: object, *args) -> None:
        super().__init__(invalid_object, *args)
        self._invalid_object = invalid_object


class SymbolSpaceError(VolatilityException):
    """Thrown when an error occurs dealing with Symbols and Symbolspaces"""


class LayerException(VolatilityException):
    """Thrown when an error occurs dealing with memory and layers"""


class StructureException(VolatilityException):
    """Thrown when an error occurs dealing with an expected structure type"""
