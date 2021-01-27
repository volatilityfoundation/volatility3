# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
"""Volatility 3 framework."""
# Check the python version to ensure it's suitable
# We currently require 3.5.3 since 3.5.1 has no typing.Type and 3.5.2 is broken for ''/delayed encapsulated types
import glob
import sys

required_python_version = (3, 5, 3)
if (sys.version_info.major != required_python_version[0] or sys.version_info.minor < required_python_version[1] or
    (sys.version_info.minor == required_python_version[1] and sys.version_info.micro < required_python_version[2])):
    raise RuntimeError(
        "Volatility framework requires python version {}.{}.{} or greater".format(*required_python_version))

import importlib
import inspect
import logging
import os
from typing import Any, Dict, Generator, List, Tuple, Type, TypeVar

from volatility3.framework import constants, interfaces

# ##
#
# SemVer version scheme
#
# Increment the:
#
#     MAJOR version when you make incompatible API changes,
#     MINOR version when you add functionality in a backwards compatible manner, and
#     PATCH version when you make backwards compatible bug fixes.


def interface_version() -> Tuple[int, int, int]:
    """Provides the so version number of the library."""
    return constants.VERSION_MAJOR, constants.VERSION_MINOR, constants.VERSION_PATCH


vollog = logging.getLogger(__name__)


def require_interface_version(*args) -> None:
    """Checks the required version of a plugin."""
    if len(args):
        if args[0] != interface_version()[0]:
            raise RuntimeError("Framework interface version {} is incompatible with required version {}".format(
                interface_version()[0], args[0]))
        if len(args) > 1:
            if args[1] > interface_version()[1]:
                raise RuntimeError(
                    "Framework interface version {} is an older revision than the required version {}".format(
                        ".".join([str(x) for x in interface_version()[0:1]]), ".".join([str(x) for x in args[0:2]])))


class noninheritable(object):

    def __init__(self, value: Any, cls: Type) -> None:
        self.default_value = value
        self.cls = cls

    def __get__(self, obj: Any, type: Type = None) -> Any:
        if type == self.cls:
            if hasattr(self.default_value, '__get__'):
                return self.default_value.__get__(obj, type)
            return self.default_value
        raise AttributeError


def hide_from_subclasses(cls: Type) -> Type:
    cls.hidden = noninheritable(True, cls)
    return cls


T = TypeVar('T')


def class_subclasses(cls: Type[T]) -> Generator[Type[T], None, None]:
    """Returns all the (recursive) subclasses of a given class."""
    if not inspect.isclass(cls):
        raise TypeError("class_subclasses parameter not a valid class: {}".format(cls))
    for clazz in cls.__subclasses__():
        # The typing system is not clever enough to realize that clazz has a hidden attr after the hasattr check
        if not hasattr(clazz, 'hidden') or not clazz.hidden:  # type: ignore
            yield clazz
        for return_value in class_subclasses(clazz):
            yield return_value


def import_files(base_module, ignore_errors = False) -> List[str]:
    """Imports all plugins present under plugins module namespace."""
    failures = []
    if not isinstance(base_module.__path__, list):
        raise TypeError("[base_module].__path__ must be a list of paths")
    vollog.log(constants.LOGLEVEL_VVVV,
               "Importing from the following paths: {}".format(", ".join(base_module.__path__)))
    for path in base_module.__path__:
        for root, _, files in os.walk(path, followlinks = True):
            # TODO: Figure out how to import pycache files
            if root.endswith("__pycache__"):
                continue
            for f in files:
                if (f.endswith(".py") or f.endswith(".pyc") or f.endswith(".pyo")) and not f.startswith("__"):
                    modpath = os.path.join(root[len(path) + len(os.path.sep):], f[:f.rfind(".")])
                    module = modpath.replace(os.path.sep, ".")
                    if base_module.__name__ + "." + module not in sys.modules:
                        try:
                            importlib.import_module(base_module.__name__ + "." + module)
                        except ImportError as e:
                            vollog.debug(str(e))
                            vollog.debug("Failed to import module {} based on file: {}".format(
                                base_module.__name__ + "." + module, modpath))
                            failures.append(base_module.__name__ + "." + module)
                            if not ignore_errors:
                                raise
    return failures


def list_plugins() -> Dict[str, Type[interfaces.plugins.PluginInterface]]:
    plugin_list = {}
    for plugin in class_subclasses(interfaces.plugins.PluginInterface):
        plugin_name = plugin.__module__ + "." + plugin.__name__
        if plugin_name.startswith("volatility3.plugins."):
            plugin_name = plugin_name[len("volatility3.plugins."):]
        plugin_list[plugin_name] = plugin
    return plugin_list


def clear_cache(complete = False):
    glob_pattern = '*.cache'
    if not complete:
        glob_pattern = 'data_' + glob_pattern
    for cache_filename in glob.glob(os.path.join(constants.CACHE_PATH, glob_pattern)):
        os.unlink(cache_filename)
