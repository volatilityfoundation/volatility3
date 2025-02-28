from importlib import abc
from typing import Any, Callable

class classproperty(property):
    def __init__(self, func: Callable[[_S], _T]) -> None: ...
    def __get__(self, obj: Any, type: _S | None = None) -> _T: ...

class WarningFindSpec(abc.MetaPathFinder):
    @staticmethod
    def find_spec(
        fullname: str, path: list[str] | None, target: None = None, **kwargs
    ) -> None: ...

warning_find_spec: list[abc.MetaPathFinder]
