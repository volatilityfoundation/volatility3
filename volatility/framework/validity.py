"""A set of classes providing consistent type checking and error handling for type/class validity
"""
import typing

ProgressCallback = typing.Optional[typing.Callable[[float, str], None]]


class ValidityRoutines(object):
    """Class to hold all validation routines, such as type checking

    Contains only private class methods, including `_check_type(cls, value, valid_type)` and
    `_check_class(cls, klass, valid_class)`.  These may eventually be made obsolete by PEP 484
    and appropriate static type verification by software such as mypy.

    These are currently implemented by assertions that will be optimized out of production code.
    """

    V = typing.TypeVar('V')

    @classmethod
    def _check_type(cls, value: V, valid_type: typing.Type) -> V:
        """Checks that value is an instance of valid_type, and returns value if it is, or throws a TypeError otherwise

        Args:
            value: The value of which to validate the type
            valid_type: The type against which to validate
        """
        assert isinstance(value,
                          valid_type), cls.__name__ + " expected " + valid_type.__name__ + ", not " + type(
            value).__name__
        return value

    @classmethod
    def _check_class(cls, klass: typing.Type, valid_class: typing.Type) -> typing.Type:
        """Checks that class is an instance of valid_class, and returns klass if it is, or throws a TypeError otherwise

        Args:
            klass: Class to validate
            valid_class: Valid class against which to check class validity
        """
        assert issubclass(klass,
                          valid_class), cls.__name__ + " expected " + valid_class.__name__ + ", not " + klass.__name__
        return klass
