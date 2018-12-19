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

from typing import Optional, Union

from volatility.framework import interfaces, objects, constants


def array_to_string(array: objects.Array, count: Optional[int] = None,
                    errors: str = 'replace') -> interfaces.objects.ObjectInterface:
    """Takes a volatility Array of characters and returns a string"""
    # TODO: Consider checking the Array's target is a native char
    if count is None:
        count = array.vol.count
    if not isinstance(array, objects.Array):
        raise TypeError("Array_to_string takes an Array of char")

    return array.cast("string", max_length = count, errors = errors)


def pointer_to_string(pointer: objects.Pointer, count: int, errors: str = 'replace'):
    """Takes a volatility Pointer to characters and returns a string"""
    if not isinstance(pointer, objects.Pointer):
        raise TypeError("pointer_to_string takes a Pointer")
    if count < 1:
        raise ValueError("pointer_to_string requires a positive count")
    char = pointer.dereference()
    return char.cast("string", max_length = count, errors = errors)


def array_of_pointers(array: interfaces.objects.ObjectInterface, count: int,
                      subtype: Union[str, interfaces.objects.Template],
                      context: interfaces.context.ContextInterface) -> interfaces.objects.ObjectInterface:
    """Takes an object, and recasts it as an array of pointers to subtype"""
    symbol_table = array.vol.type_name.split(constants.BANG)[0]
    if isinstance(subtype, str) and context is not None:
        subtype = context.symbol_space.get_type(subtype)
    if not isinstance(subtype, interfaces.objects.Template) or subtype is None:
        raise TypeError("Subtype must be a valid template (or string name of an object template)")
    subtype_pointer = context.symbol_space.get_type(symbol_table + constants.BANG + "pointer")
    subtype_pointer.update_vol(subtype = subtype)
    return array.cast("array", count = count, subtype = subtype_pointer)
