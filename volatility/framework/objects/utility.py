from volatility.framework.objects import Array


def array_to_string(array, errors = 'replace'):
    """Takes a volatility Array of characters and returns a string"""
    # TODO: Consider checking the Array's target is a native char
    if not isinstance(array, Array):
        raise TypeError("Array_to_string takes an Array of char")
    return array.cast("string", max_length = array.vol.count, errors = errors)
