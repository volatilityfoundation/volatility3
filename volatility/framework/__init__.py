"""Volatility 3 framework"""
import inspect

# ##
#
# Libtool version scheme
#
# Current - The number of the current interface exported by the library
# Revision - The implementation number of the most recent interface exported by this library
# Age - The number of previous additional interfaces supported by this library
#
# 1. If the source changes, increment the revision
# 2. If the interface has changed, increment current, set revision to 0
# 3. If only additions to the interface have been made, increment age
# 4. If changes or removals of the interface have been made, set age to 0
import sys

CURRENT = 3  # Number of releases of the library with any change
REVISION = 0  # Number of changes that don't affect the interface
AGE = 0  # Number of consecutive versions of the interface the current version supports


def version():
    """Provides the so version number of the library"""
    return CURRENT - AGE, AGE, REVISION


def require_version(*args):
    """Checks the required version of a plugin"""
    if len(args):
        if args[0] != version()[0]:
            raise RuntimeError("Framework version " + str(version()[0]) +
                               " is incompatible with required version " + str(args[0]))
        if len(args) > 1:
            if args[1] > version()[1]:
                raise RuntimeError("Framework version " + ".".join([str(x) for x in version()[0:1]]) +
                                   " is an older revision than the required version " +
                                   ".".join([str(x) for x in args[0:2]]))


def class_subclasses(cls):
    """Returns all the (recursive) subclasses of a given class"""
    if not inspect.isclass(cls):
        raise TypeError(repr(cls) + " is not a class.")
    for clazz in cls.__subclasses__():
        yield clazz
        for return_value in class_subclasses(clazz):
            yield return_value


# Check the python version to ensure it's suitable
if sys.version_info.major != 3 or sys.version_info.minor < 4:
    raise RuntimeError("Volatility framework requires python version 3.4 or greater")

from volatility.framework import interfaces, symbols, layers, contexts, configuration
