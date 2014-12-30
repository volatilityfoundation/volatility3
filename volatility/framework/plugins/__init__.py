# TODO: Code to import all the py/pyc files available (but not both).
# TODO: Code to return a none-instantiated list of plugin classes.

import os
import sys
import logging
import inspect

import volatility.plugins as plugins


logger = logging.getLogger(__name__)


def class_subclasses(cls):
    """Returns all the (recursive) subclasses of a given class"""
    if not inspect.isclass(cls):
        raise TypeError(repr(cls) + " is not a class.")
    for clazz in cls.__subclasses__():
        yield clazz
        for return_value in class_subclasses(clazz):
            yield return_value


def import_plugins():
    """Imports all plugins present under plugins path"""
    if not isinstance(plugins.__path__, list):
        raise TypeError("Plugins.__path__ must be a list of paths")
    for path in plugins.__path__:
        for root, _, files in os.walk(path, followlinks = True):
            # TODO: Figure out how to import pycache files
            if root.endswith("__pycache__"):
                continue
            for f in files:
                if (f.endswith(".py") or f.endswith(".pyc") or f.endswith(".pyo")) and not f.startswith("__"):
                    path = os.path.join(root[len(path) + len(os.path.sep):], f[:f.rfind(".")])
                    module = path.replace(os.path.sep, ".")
                    if module not in sys.modules:
                        try:
                            logging.debug("Importing volatility.plugins." + str(module))
                            __import__("volatility.plugins." + str(module))
                        except ImportError:
                            logger.warning("Failed to import module " + str(module) + " based on file " + path)
                            raise
                    else:
                        logger.info("Skipping existing module " + str(module))
