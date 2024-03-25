# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

import re
from typing import Generator, List, Tuple


class MultiRegexp(object):
    """Algorithm for multi-string matching."""

    def __init__(self) -> None:
        self._pattern_strings: List[bytes] = []
        self._regex = re.compile(b"")

    def add_pattern(self, pattern: bytes) -> None:
        self._pattern_strings.append(pattern)

    def preprocess(self) -> None:
        if not self._pattern_strings:
            raise ValueError("No strings to compile into a regular expression")
        self._regex = re.compile(b"|".join(map(re.escape, self._pattern_strings)))

    def search(self, haystack: bytes) -> Generator[Tuple[int, bytes], None, None]:
        if not isinstance(haystack, bytes):
            raise TypeError("Search haystack must be a byte string")
        if not self._regex.pattern:
            raise ValueError(
                "MultiRegexp cannot be used with an empty set of search strings"
            )
        for match in re.finditer(self._regex, haystack):
            yield (match.start(0), match.group())
