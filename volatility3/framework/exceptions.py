# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
"""A list of potential exceptions that volatility can throw.

These include exceptions that can be thrown on errors by the symbol
space or symbol tables, and by layers when an address is invalid.  The
:class:`PagedInvalidAddressException` contains information about the
size of the invalid page.
"""
from typing import Dict, Optional

from volatility3.framework import interfaces


class VolatilityException(Exception):
    """Class to allow filtering of all VolatilityExceptions."""


class PluginVersionException(VolatilityException):
    """Class to allow determining that a required plugin has an invalid
    version."""


class PluginRequirementException(VolatilityException):
    """Class to allow plugins to indicate that a requirement has not been
    fulfilled."""


class SymbolError(VolatilityException):
    """Thrown when a symbol lookup has failed."""

    def __init__(
        self, symbol_name: Optional[str], table_name: Optional[str], *args
    ) -> None:
        super().__init__(*args)
        self.symbol_name = symbol_name
        self.table_name = table_name


class LayerException(VolatilityException):
    """Thrown when an error occurs dealing with memory and layers."""

    def __init__(self, layer_name: str, *args) -> None:
        super().__init__(*args)
        self.layer_name = layer_name


class InvalidAddressException(LayerException):
    """Thrown when an address is not valid in the layer it was requested."""

    def __init__(self, layer_name: str, invalid_address: int, *args) -> None:
        super().__init__(layer_name, *args)
        self.invalid_address = invalid_address


class PagedInvalidAddressException(InvalidAddressException):
    """Thrown when an address is not valid in the paged space in which it was
    request.  This is a subclass of InvalidAddressException and is only
    thrown from a paged layer.  In most circumstances :class:`InvalidAddressException`
    is the correct exception to throw, since this will catch all invalid
    mappings (including paged ones).

    Includes the invalid address and the number of bits of the address
    that are invalid
    """

    def __init__(
        self,
        layer_name: str,
        invalid_address: int,
        invalid_bits: int,
        entry: int,
        *args,
    ) -> None:
        super().__init__(layer_name, invalid_address, *args)
        self.invalid_bits = invalid_bits
        self.entry = entry


class SwappedInvalidAddressException(PagedInvalidAddressException):
    """Thrown when an address is not valid in the paged layer in which it was
    requested, but expected to be in an associated swap layer.

    Includes the swap lookup, as well as the invalid address and the bits of
    the lookup that were invalid.
    """

    def __init__(
        self,
        layer_name: str,
        invalid_address: int,
        invalid_bits: int,
        entry: int,
        swap_offset: int,
        *args,
    ) -> None:
        super().__init__(layer_name, invalid_address, invalid_bits, entry, *args)
        self.swap_offset = swap_offset


class SymbolSpaceError(VolatilityException):
    """Thrown when an error occurs dealing with Symbolspaces and SymbolTables."""


class UnsatisfiedException(VolatilityException):
    def __init__(
        self, unsatisfied: Dict[str, interfaces.configuration.RequirementInterface]
    ) -> None:
        super().__init__()
        self.unsatisfied = unsatisfied


class MissingModuleException(VolatilityException):
    def __init__(self, module: str, *args) -> None:
        super().__init__(*args)
        self.module = module


class RenderException(VolatilityException):
    """Thrown if there is an error during rendering"""


class OfflineException(VolatilityException):
    """Throw when a remote resource is requested but Volatility is in offline mode"""

    def __init__(self, url: str, *args) -> None:
        super().__init__(*args)
        self._url = url

    def __str__(self):
        return f"Volatility 3 is offline: unable to access {self._url}"
