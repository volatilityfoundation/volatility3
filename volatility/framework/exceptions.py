# This file was contributed to the Volatility Framework Version 3.
# Copyright (C) 2018 Volatility Foundation.
#
# THE LICENSED WORK IS PROVIDED UNDER THE TERMS OF THE Volatility Contributors
# Public License V1.0("LICENSE") AS FIRST COMPLETED BY: Volatility Foundation,
# Inc. ANY USE, PUBLIC DISPLAY, PUBLIC PERFORMANCE, REPRODUCTION OR DISTRIBUTION
# OF, OR PREPARATION OF SUBSEQUENT WORKS, DERIVATIVE WORKS OR DERIVED WORKS BASED
# ON, THE LICENSED WORK CONSTITUTES RECIPIENT'S ACCEPTANCE OF THIS LICENSE AND ITS
# TERMS, WHETHER OR NOT SUCH RECIPIENT READS THE TERMS OF THE LICENSE. "LICENSED
# WORK,” “RECIPIENT" AND “DISTRIBUTOR" ARE DEFINED IN THE LICENSE. A COPY OF THE
# LICENSE IS LOCATED IN THE TEXT FILE ENTITLED "LICENSE.txt" ACCOMPANYING THE
# CONTENTS OF THIS FILE. IF A COPY OF THE LICENSE DOES NOT ACCOMPANY THIS FILE, A
# COPY OF THE LICENSE MAY ALSO BE OBTAINED AT THE FOLLOWING WEB SITE:
# https://www.volatilityfoundation.org/license/vcpl_v1.0
#
# Software distributed under the License is distributed on an "AS IS" basis,
# WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License for the
# specific language governing rights and limitations under the License.
#
"""A list of potential exceptions that volatility can throw.

These include exceptions that can be thrown on errors by the symbol space or symbol tables, and by layers when
an address is invalid.  The :class:`PagedInvalidAddressException` contains information about the size of the invalid
page.
"""
from typing import Dict

from volatility.framework import interfaces


class VolatilityException(Exception):
    """Class to allow filtering of all VolatilityExceptions"""


class PluginRequirementException(VolatilityException):
    """Class to allow plugins to indicate that a requirement has not been fulfilled"""


class SymbolError(VolatilityException):
    """Thrown when a symbol lookup has failed"""


class InvalidAddressException(VolatilityException):
    """Thrown when an address is not valid in the space it was requested"""

    def __init__(self, layer_name: str, invalid_address: int, *args) -> None:
        super().__init__(layer_name, invalid_address, *args)
        self.invalid_address = invalid_address
        self.layer_name = layer_name


class PagedInvalidAddressException(InvalidAddressException):
    """Thrown when an address is not valid in the paged space in which it was request

    Includes the invalid address and the number of bits of the address that are invalid
    """

    def __init__(self, layer_name: str, invalid_address: int, invalid_bits: int, entry: int, *args) -> None:
        super().__init__(layer_name, invalid_address, *args)
        self.invalid_bits = invalid_bits
        self.entry = entry


class SwappedInvalidAddressException(PagedInvalidAddressException):
    """Thrown when an address is not valid in the paged space in which it was requested,
    but expected to be in swap space

    Includes the swap lookup"""

    def __init__(self, layer_name: str, invalid_address: int, invalid_bits: int, entry: int, swap_offset: int,
                 *args) -> None:
        super().__init__(layer_name, invalid_address, invalid_bits, entry, *args)
        self.swap_offset = swap_offset


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


class MissingStructureException(VolatilityException):
    """Thrown when an error occurs due to an expected structure not being present"""


class UnsatisfiedException(VolatilityException):

    def __init__(self, unsatisfied: Dict[str, interfaces.configuration.RequirementInterface]) -> None:
        super().__init__()
        self.unsatisfied = unsatisfied
