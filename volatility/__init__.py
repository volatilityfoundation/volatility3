# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
"""Volatility 3 - An open-source memory forensics framework"""
import inspect
import sys
from importlib import abc
from typing import List, TypeVar, Callable, Any, Optional

_T = TypeVar("_T")
_S = TypeVar("_S")

CACHING = True


class classproperty(property):
    """Class property decorator.

    Note this will change the return type
    """

    def __init__(self, func: Callable[[_S], _T]) -> None:
        self._func = func
        super().__init__()

    def __get__(self, obj: Any, type: Optional[_S] = None) -> _T:
        if type is not None:
            return self._func(type)
        raise TypeError("Classproperty was not applied properly")


class WarningFindSpec(abc.MetaPathFinder):
    """Checks import attempts and throws a warning if the name shouldn't be
    used."""

    @staticmethod
    def find_spec(fullname: str, path: Optional[List[str]], target: None = None, **kwargs) -> None:
        """Mock find_spec method that just checks the name, this must go
        first."""
        if fullname.startswith("volatility.framework.plugins."):
            warning = "Please do not use the volatility.framework.plugins namespace directly, only use volatility.plugins"
            # Pyinstaller uses walk_packages to import, but needs to read the modules to figure out dependencies
            # As such, we only print the warning when directly imported rather than from within walk_packages
            if inspect.stack()[-2].function != 'walk_packages':
                raise Warning(warning)


warning_find_spec = [WarningFindSpec()]  # type: List[abc.MetaPathFinder]
sys.meta_path = warning_find_spec + sys.meta_path

# We point the volatility.plugins __path__ variable at BOTH
#   volatility/plugins
#   volatility/framework/plugins
# in that order.
#
# This will allow our users to override any component of any plugin without monkey patching,
# but it also allows us to clear out the plugins directory to get back to proper functionality.
# This offered the greatest flexibility for users whilst allowing us to keep the core separate and clean.
#
# This means that all plugins should be imported as volatility.plugins (otherwise they'll be imported twice,
# once as volatility.plugins.NAME and once as volatility.framework.plugins.NAME).  We therefore throw an error
# if anyone tries to import anything under the volatility.framework.plugins.* namespace
#
# The remediation is to only ever import form volatility.plugins instead.
