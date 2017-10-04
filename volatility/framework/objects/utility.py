from volatility.framework import objects


def array_to_string(array, count = None, errors = 'replace'):
    """Takes a volatility Array of characters and returns a string"""
    # TODO: Consider checking the Array's target is a native char
    if count is None:
        count = array.vol.count
    if not isinstance(array, objects.Array):
        raise TypeError("Array_to_string takes an Array of char")
    return array.cast("string", max_length = count, errors = errors)


def pointer_to_string(pointer, count, errors = 'replace'):
    """Takes a volatility Pointer to characters and returns a string"""
    if not isinstance(pointer, objects.Pointer):
        raise TypeError("pointer_to_string takes a Pointer")
    if count < 1:
        raise ValueError("pointer_to_string requires a positive count")
    char = pointer.dereference()
    return char.cast("string", max_length = count, errors = errors)


def array_of_pointers(array, count, subtype = None):
    """Takes an object, and recasts it as an array of pointers to subtype"""
    subtype_pointer = objects.templates.ObjectTemplate(objects.Pointer, type_name = 'pointer', subtype = subtype)
    return array.cast("array", count = count, subtype = subtype_pointer)
