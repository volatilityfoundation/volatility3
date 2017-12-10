import collections
import typing

from volatility.framework import interfaces, validity


class Flags(validity.ValidityRoutines):
    """Object that converts an integer into a set of flags based on their masks"""

    def __init__(self, choices: typing.Mapping[str, int] = None) -> None:
        self._check_type(choices, collections.Mapping)
        for k, v in choices.items():
            self._check_type(k, str)
            self._check_type(v, int)
        self._choices = interfaces.objects.ReadOnlyMapping(choices)

    @property
    def choices(self) -> interfaces.objects.ReadOnlyMapping:
        return self._choices

    def __call__(self, value: int) -> typing.List[str]:
        """Return the appropriate Flags """
        result = []
        for k, v in self.choices.items():
            if value & v:
                result.append(k)
        return result
