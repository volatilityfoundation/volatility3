from volatility.framework.objects import Array, Pointer


def array_to_string(array, errors = 'replace'):
    """Takes a volatility Array of characters and returns a string"""
    # TODO: Consider checking the Array's target is a native char
    if not isinstance(array, Array):
        raise TypeError("Array_to_string takes an Array of char")
    return array.cast("string", max_length = array.vol.count, errors = errors)

def pointer_to_string(pointer, count, errors = 'replace'):
    """Takes a volatility Pointer to characters and returns a string"""
    if not isinstance(pointer, Pointer):
        raise TypeError("pointer_to_string takes a Pointer")
    if count < 1:
        raise ValueError("pointer_to_string requires a positive count")
    char = pointer.dereference()
    return char.cast("string", max_length = count, errors=errors)
