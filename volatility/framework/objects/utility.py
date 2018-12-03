import datetime
import typing

from volatility.framework import interfaces, objects, renderers, constants


def array_to_string(array: objects.Array,
                    count: typing.Optional[int] = None,
                    errors: str = 'replace') -> interfaces.objects.ObjectInterface:
    """Takes a volatility Array of characters and returns a string"""
    # TODO: Consider checking the Array's target is a native char
    if count is None:
        count = array.vol.count
    if not isinstance(array, objects.Array):
        raise TypeError("Array_to_string takes an Array of char")

    return array.cast("string", max_length = count, errors = errors)


def pointer_to_string(pointer: objects.Pointer,
                      count: int,
                      errors: str = 'replace'):
    """Takes a volatility Pointer to characters and returns a string"""
    if not isinstance(pointer, objects.Pointer):
        raise TypeError("pointer_to_string takes a Pointer")
    if count < 1:
        raise ValueError("pointer_to_string requires a positive count")
    char = pointer.dereference()
    return char.cast("string", max_length = count, errors = errors)


def array_of_pointers(array: interfaces.objects.ObjectInterface,
                      count: int,
                      subtype: typing.Union[str, interfaces.objects.Template],
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


def wintime_to_datetime(wintime: int) -> typing.Union[
    interfaces.renderers.BaseAbsentValue, datetime.datetime]:
    unix_time = wintime // 10000000
    if unix_time == 0:
        return renderers.NotApplicableValue()
    unix_time = unix_time - 11644473600
    try:
        return datetime.datetime.utcfromtimestamp(unix_time)
    except ValueError:
        return renderers.UnparsableValue()

def unixtime_to_datetime(unixtime: int) -> typing.Union[
    interfaces.renderers.BaseAbsentValue, datetime.datetime]:

    ret = renderers.NotApplicableValue()
    
    if unixtime > 0:
        try:
            ret = datetime.datetime.utcfromtimestamp(unixtime)
        except ValueError:
            pass

    return ret

def round(addr: int, align: int, up: bool = False) -> int:
    """Round an address up or down based on an alignment.

    Args:
        addr: the address
        align: the alignment value
        up: Whether to round up or not

    Returns:
        The aligned address
    """

    if addr % align == 0:
        return addr
    else:
        if up:
            return (addr + (align - (addr % align)))
        return (addr - (addr % align))
