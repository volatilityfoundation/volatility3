# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

from typing import List, Mapping

from volatility3.framework import interfaces


class Flags:
    """Object that converts an integer into a set of flags based on their
    masks."""

    def __init__(self, choices: Mapping[str, int]) -> None:
        self._choices = interfaces.objects.ReadOnlyMapping(choices)

    @property
    def choices(self) -> interfaces.objects.ReadOnlyMapping:
        return self._choices

    def __call__(self, value: int) -> List[str]:
        """Return the appropriate Flags."""
        result = []
        for k, v in self.choices.items():
            if value & v:
                result.append(k)
        return result
