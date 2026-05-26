# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

import re
import logging
from typing import Optional, Union

from volatility3.framework import interfaces, objects, constants, exceptions

vollog = logging.getLogger(__name__)


def rol(value: int, count: int, max_bits: int = 64) -> int:
    """A rotate-left instruction in Python"""
    max_bits_mask = (1 << max_bits) - 1
    return (value << count % max_bits) & max_bits_mask | (
        (value & max_bits_mask) >> (max_bits - (count % max_bits))
    )


def bswap_32(value: int) -> int:
    value = ((value << 8) & 0xFF00FF00) | ((value >> 8) & 0x00FF00FF)

    return ((value << 16) | (value >> 16)) & 0xFFFFFFFF


def bswap_64(value: int) -> int:
    low = bswap_32(value >> 32)
    high = bswap_32(value & 0xFFFFFFFF)

    return ((high << 32) | low) & 0xFFFFFFFFFFFFFFFF


def array_to_string(
    array: "objects.Array",
    count: Optional[int] = None,
    errors: str = "replace",
    block_size=32,
    encoding="utf-8",
) -> str:
    """Takes a Volatility 'Array' of characters and returns a Python string.

    Args:
        array: The Volatility `Array` object containing character elements.
        count: Optional maximum number of characters to convert. If None, the function
               processes the entire array.
        errors: Specifies error handling behavior for decoding, defaulting to "replace".
        block_size: Reading block size. Defaults to 32

    Returns:
        A decoded string representation of the character array.
    """
    # TODO: Consider checking the Array's target is a native char
    if not isinstance(array, objects.Array):
        raise TypeError("Array_to_string takes an Array of char")

    if count is None:
        count = array.vol.count

    return address_to_string(
        context=array._context,
        layer_name=array.vol.layer_name,
        address=array.vol.offset,
        count=count,
        errors=errors,
        block_size=block_size,
        encoding=encoding,
    )


def pointer_to_string(
    pointer: "objects.Pointer",
    count: int,
    errors: str = "replace",
    block_size=32,
    encoding="utf-8",
) -> str:
    """Takes a Volatility 'Pointer' to characters and returns a Python string.

    Args:
        pointer: A `Pointer` object containing character elements.
        count: Optional maximum number of characters to convert. If None, the function
               processes the entire array.
        errors: Specifies error handling behavior for decoding, defaulting to "replace".
        block_size: Reading block size. Defaults to 32

    Returns:
        A decoded string representation of the data referenced by the pointer.
    """
    if not isinstance(pointer, objects.Pointer):
        raise TypeError("pointer_to_string takes a Pointer")

    if count < 1:
        raise ValueError("pointer_to_string requires a positive count")

    return address_to_string(
        context=pointer._context,
        layer_name=pointer.vol.layer_name,
        address=pointer,
        count=count,
        errors=errors,
        block_size=block_size,
        encoding=encoding,
    )


def gather_contiguous_bytes_from_address(
    context, data_layer, starting_address: int, count: int
) -> bytes:
    """
    This method reconstructs a string from memory while also carefully examining each page

    It goes page-by-page reading the bytes. This is done by calculating page boundaries
    and then only reading one page at a time.

    If a page is missing, the code initially catches the exception.
    If data is non-empty (meaning at least one read succeeded), then we return what was read
    If the first page fails, then we re-raise the exception
    """

    data = b""

    if isinstance(data_layer, interfaces.layers.TranslationLayerInterface):
        last_address = starting_address

        for address, length, _, _, _ in data_layer.mapping(
            offset=starting_address, length=count, ignore_errors=True
        ):
            # we hit a swapped out page
            if last_address != address:
                break

            data += data_layer.read(address, length)

            last_address = address + length

    elif starting_address + count < data_layer.maximum_address:
        data = data_layer.read(starting_address, count)

    # if we were able to read from the first page, we want to try and construct the string
    # if the first page fails -> throw exception
    if data:
        return data
    else:
        raise exceptions.InvalidAddressException(
            layer_name=data_layer, invalid_address=starting_address
        )


def bytes_to_decoded_string(
    data: bytes, encoding: str, errors: str, return_truncated: bool = True
) -> str:
    """
    Args:
        data: The `bytes` buffer containing the string of a string at offset 0
        encoding: An encoding value for the encoding parameter of `bytes.decode`
        errors: An errors value for the errors parameter of `bytes.decode`
        return_truncated: Dictates whether truncated strings should be returned or
        if a ValueError should be thrown if a truncated (broken) string was decoded
    Returns:
        bytes: The decoded string starting at offset of data

    This function takes a bytes buffer that contains at a string of unknown
    length starting at the first byte, and returns the properly decoded string

    It starts by using Python's `bytes.decode` to attempt to decode the entire string
    It then finds the termination character (\ufffd or \x00) and splices the string
    Finally, it returns this spliced string after its been decoded with the
        caller-specified encoding
    """
    # this is the standard byte used to replace bad unicode characters
    unicode_replacement_char = "\ufffd"

    # used to find the terminating byte
    termination_re = re.compile(f"{unicode_replacement_char}|\x00")

    # run over the entire string, letting Python replace invalid characters
    full_decoded_string = data.decode(encoding=encoding, errors="replace")

    # stop at the first terminating character or get the whole string if not found
    try:
        idx = termination_re.search(full_decoded_string).start()
    except AttributeError:
        if return_truncated:
            idx = len(full_decoded_string)
        else:
            raise ValueError(
                "return_truncated set to False and truncated string decoded."
            )

    # cut at terminating byte, if found
    data = bytes(full_decoded_string[:idx], encoding=encoding)

    # return with caller-specified encoding and errors
    return data.decode(encoding=encoding, errors=errors)


def address_to_string(
    context: interfaces.context.ContextInterface,
    layer_name: str,
    address: int,
    count: int,
    errors: str = "replace",
    block_size=32,
    encoding="utf-8",
) -> str:
    """Reads a null-terminated string from a given specified memory address, processing
       it in blocks for efficiency.

    Args:
        context: The context used to retrieve memory layers and symbol tables
        layer_name: The name of the memory layer to read from
        address: The address where the string is located in memory
        count: The number of bytes to read
        errors: The error handling scheme to use for encoding errors. Defaults to "replace"
        block_size: Reading block size. Defaults to 32

    Returns:
        The decoded string extracted from memory.
    """
    if not isinstance(address, int):
        raise TypeError("Address must be a valid integer")

    if count < 1:
        raise ValueError("Count must be greater than 0")

    layer = context.layers[layer_name]

    data = gather_contiguous_bytes_from_address(context, layer, address, count)

    return bytes_to_decoded_string(data=data, errors=errors, encoding=encoding)


def array_of_pointers(
    array: interfaces.objects.ObjectInterface,
    count: int,
    subtype: Union[str, interfaces.objects.Template],
    context: interfaces.context.ContextInterface,
) -> interfaces.objects.ObjectInterface:
    """Takes an object, and recasts it as an array of pointers to subtype."""
    symbol_table = array.vol.type_name.split(constants.BANG)[0]
    if isinstance(subtype, str) and context is not None:
        subtype = context.symbol_space.get_type(subtype)
    if not isinstance(subtype, interfaces.objects.Template) or subtype is None:
        raise TypeError(
            "Subtype must be a valid template (or string name of an object template)"
        )
    # We have to clone the pointer class, or we'll be defining the pointer subtype for all future pointers
    subtype_pointer = context.symbol_space.get_type(
        symbol_table + constants.BANG + "pointer"
    ).clone()
    subtype_pointer.update_vol(subtype=subtype)
    return array.cast("array", count=count, subtype=subtype_pointer)


def dynamically_sized_array_of_pointers(
    context: interfaces.context.ContextInterface,
    array: interfaces.objects.ObjectInterface,
    subtype: Union[str, interfaces.objects.Template],
    iterator_guard_value: int,
    stop_value: int = 0,
    stop_on_invalid_pointers: bool = True,
) -> interfaces.objects.ObjectInterface:
    """Iterates over a dynamically sized array of pointers (e.g. NULL-terminated).
    Array iteration should always be performed with an arbitrary guard value as maximum size,
    to prevent running forever in case something unexpected happens.

        Args:
            context: The context on which to operate.
            array: The object to cast to an array.
            iterator_guard_value: Stop iterating when the iterator index is greater than this value. This is an extra-safety against smearing.
            subtype: The subtype of the array's pointers.
            stop_value: Stop value used to determine when to terminate iteration once it is encountered. Defaults to 0 (NULL-terminated arrays).
            stop_on_invalid_pointers: Determines whether to stop iterating or not when an invalid pointer is encountered. This can be useful for arrays
    that are known to have smeared entries before the end.

        Returns:
            An array of pointer objects
    """
    new_count = 0
    sym_table_name = array.get_symbol_table_name()
    sym_table = context.symbol_space[sym_table_name]
    ptr_size = sym_table.get_type("pointer").size
    layer_name = array.vol.layer_name

    offset = array.vol.offset
    entry = None
    while entry != stop_value and new_count < iterator_guard_value:
        try:
            entry = context.object(
                sym_table_name + constants.BANG + "pointer",
                offset=offset,
                layer_name=layer_name,
            )
        except exceptions.InvalidAddressException:
            break

        if not entry.is_readable() and stop_on_invalid_pointers:
            break

        offset += ptr_size
        new_count += 1
    else:
        vollog.log(
            constants.LOGLEVEL_V,
            f"""Iterator guard value {iterator_guard_value} reached while iterating over array at offset {array.vol.offset:#x}.\
 This means that there is a bug (e.g. smearing) with this array, or that it may contain valid entries past the iterator guard value.""",
        )

    # Leverage the "Array" object instead of returning a Python list
    return array_of_pointers(
        array=array, count=new_count, subtype=subtype, context=context
    )
