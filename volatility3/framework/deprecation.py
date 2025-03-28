# This file is Copyright 2025 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

# This file contains the Deprecation class used to deprecate methods in an orderly manner

import warnings
import functools
import inspect

from typing import Callable, Tuple

from volatility3.framework import interfaces, exceptions
from volatility3.framework.configuration import requirements


def method_being_removed(message: str, removal_date: str):
    """A decorator for marking functions as being removed in the future and without a replacement.
       Callers to this function should explicitly list the API paths that should be used instead.

    Args:
        message: A message added to the standard deprecation warning. Should include the replacement API paths
        removal_date: A YYYY-MM-DD formatted date of when the function will be removed from the framework
    """

    def decorator(deprecated_func):
        @functools.wraps(deprecated_func)
        def wrapper(*args, **kwargs):
            warnings.warn(
                f"This API ({deprecated_func.__module__}.{deprecated_func.__qualname__}) will be removed in the first release after {removal_date}. {message}",
                FutureWarning,
            )
            return deprecated_func(*args, **kwargs)

        return wrapper

    return decorator


def deprecated_method(
    replacement: Callable,
    removal_date: str,
    replacement_version: Tuple[int, int, int] = None,
    additional_information: str = "",
):
    """A decorator for marking functions as deprecated.

    Args:
        replacement: The replacement function overriding the deprecated API, in the form of a Callable (typically a method)
        removal_date: A YYYY-MM-DD formatted date of when the function will be removed from the framework
        replacement_version: The "replacement" base class version that the deprecated method expects before proxying to it. This implies that "replacement" is a method from a class that inherits from VersionableInterface.
        additional_information: Information appended at the end of the deprecation message
    """

    def decorator(deprecated_func):
        @functools.wraps(deprecated_func)
        def wrapper(*args, **kwargs):
            nonlocal replacement, replacement_version, additional_information
            # Prevent version mismatches between deprecated (proxy) methods and the ones they proxy
            if (
                replacement_version is not None
                and callable(replacement)
                and hasattr(replacement, "__self__")
            ):
                replacement_base_class = replacement.__self__

                # Verify that the base class inherits from VersionableInterface
                if inspect.isclass(replacement_base_class) and issubclass(
                    replacement_base_class,
                    interfaces.configuration.VersionableInterface,
                ):
                    # SemVer check
                    if not requirements.VersionRequirement.matches_required(
                        replacement_version, replacement_base_class.version
                    ):
                        raise exceptions.VersionMismatchException(
                            deprecated_func,
                            replacement_base_class,
                            replacement_version,
                            "This is a bug, the deprecated call needs to be removed and the caller needs to update their code to use the new method.",
                        )

            deprecation_msg = f"Method \"{deprecated_func.__module__ + '.' + deprecated_func.__qualname__}\" is deprecated and will be removed in the first release after {removal_date}, use \"{replacement.__module__ + '.' + replacement.__qualname__}\" instead. {additional_information}"
            warnings.warn(deprecation_msg, FutureWarning)
            # Return the wrapped function with its original arguments
            return deprecated_func(*args, **kwargs)

        return wrapper

    return decorator


def renamed_class(deprecated_class_name: str, message: str, removal_date: str):
    """A decorator for marking classes as being renamed and removed in the future.
       Callers to this function should explicitly update to use the other plugins instead.

    Args:
        deprecated_class_name: The name of the class being deprecated
        message: A message added to the standard deprecation warning. Should include the replacement API paths
        removal_date: A YYYY-MM-DD formatted date of when the function will be removed from the framework
    """

    def decorator(replacement_func):
        @functools.wraps(replacement_func)
        def wrapper(*args, **kwargs):
            warnings.warn(
                f"This plugin ({deprecated_class_name}) has been renamed and will be removed in the first release after {removal_date}. {message}",
                FutureWarning,
            )
            return replacement_func(*args, **kwargs)

        return wrapper

    return decorator


class PluginRenameClass:
    """Class to move all classmethod invocations (for when a plugin has been moved)"""

    def __init_subclass__(cls, replacement_class, removal_date, **kwargs):
        deprecated_class_name = f"{cls.__module__}.{cls.__qualname__}"
        super().__init_subclass__(**kwargs)
        for attr, value in replacement_class.__dict__.items():
            if isinstance(value, classmethod) and attr != "get_requirements":
                setattr(
                    cls,
                    attr,
                    classmethod(
                        renamed_class(
                            deprecated_class_name=deprecated_class_name,
                            removal_date=removal_date,
                            message=f"Please ensure all method calls to this plugin are replaced with calls to {replacement_class.__module__}.{replacement_class.__qualname__}",
                        )(value.__func__)
                    ),
                )
            else:
                if not attr.startswith("__"):
                    setattr(cls, attr, value)
        return super(PluginRenameClass).__init_subclass__(**kwargs)
