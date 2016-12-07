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
import logging
import os
import sys

# We use the libtool library versioning

CURRENT = 0  # Number of releases of the library with any change
REVISION = 0  # Number of changes that don't affect the interface
AGE = 0  # Number of consecutive versions of the interface the current version supports

vollog = logging.getLogger("volatility")


def interface_version():
    """Provides the so version number of the library"""
    return CURRENT - AGE, AGE, REVISION


def require_interface_version(*args):
    """Checks the required version of a plugin"""
    if len(args):
        if args[0] != interface_version()[0]:
            raise RuntimeError(
                "Framework interface version {} is incompatible with required version {}".format(interface_version()[0],
                                                                                                 args[0]))
        if len(args) > 1:
            if args[1] > interface_version()[1]:
                raise RuntimeError(
                    "Framework interface version {} is an older revision than the required version {}".format(
                        ".".join([str(x) for x in interface_version()[0:1]]),
                        ".".join([str(x) for x in args[0:2]])))


def class_subclasses(cls):
    """Returns all the (recursive) subclasses of a given class"""
    if not inspect.isclass(cls):
        raise TypeError("class_subclasses parameter not a valid class: {}".format(cls))
    for clazz in cls.__subclasses__():
        yield clazz
        for return_value in class_subclasses(clazz):
            yield return_value


def import_files(base_module):
    """Imports all plugins present under plugins path"""
    if not isinstance(base_module.__path__, list):
        raise TypeError("[base_module].__path__ must be a list of paths")
    for path in base_module.__path__:
        for root, _, files in os.walk(path, followlinks = True):
            # TODO: Figure out how to import pycache files
            if root.endswith("__pycache__"):
                continue
            for f in files:
                if (f.endswith(".py") or f.endswith(".pyc") or f.endswith(".pyo")) and not f.startswith("__"):
                    modpath = os.path.join(root[len(path) + len(os.path.sep):], f[:f.rfind(".")])
                    module = modpath.replace(os.path.sep, ".")
                    if module not in sys.modules:
                        try:
                            vollog.debug("Importing module: {}.{}".format(base_module.__name__, module))
                            __import__(base_module.__name__ + "." + module)
                        except ImportError as e:
                            vollog.debug(str(e))
                            vollog.warning("Failed to import module {} based on file: {}".format(module, modpath))
                            raise
                    else:
                        vollog.info("Skipping existing module: {}".format(module))


# Check the python version to ensure it's suitable
required_python_version = (3, 4)
if sys.version_info.major != required_python_version[0] or sys.version_info.minor < required_python_version[1]:
    raise RuntimeError("Volatility framework requires python version {}.{} or greater".format(required_python_version))
