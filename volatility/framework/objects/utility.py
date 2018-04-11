import datetime
import typing

from volatility.framework import interfaces, objects, renderers
from volatility.framework.objects import templates


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


def array_of_pointers(array: objects.Array,
                      count: int,
                      subtype: templates.ObjectTemplate = None,
                      context: interfaces.context.ContextInterface = None) -> interfaces.objects.ObjectInterface:
    """Takes an object, and recasts it as an array of pointers to subtype"""
    if isinstance(subtype, str) and context is not None:
        subtype = context.symbol_space.get_type(subtype)
    if not isinstance(subtype, templates.ObjectTemplate) or subtype is None:
        raise TypeError("Subtype must be a valid object template")
    subtype_pointer = objects.templates.ObjectTemplate(objects.Pointer, type_name = 'pointer', subtype = subtype)
    return array.cast("array", count = count, subtype = subtype_pointer)


def wintime_to_datetime(wintime: objects.Struct) -> typing.Union[
    interfaces.renderers.BaseAbsentValue, datetime.datetime]:
    unix_time = wintime.QuadPart // 10000000
    if unix_time == 0:
        return renderers.NotApplicableValue()
    unix_time = unix_time - 11644473600
    try:
        return datetime.datetime.utcfromtimestamp(unix_time)
    except ValueError:
        return renderers.UnparsableValue()
