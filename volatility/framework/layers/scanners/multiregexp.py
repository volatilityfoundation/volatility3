import re
from typing import Generator, List, Tuple, Union


class MultiRegexp(object):
    """Algorithm for multi-string matching"""

    def __init__(self) -> None:
        self._pattern_strings = []  # type: List[bytes]
        self._regex = re.compile(b'')

    def add_pattern(self, pattern: bytes) -> None:
        self._pattern_strings.append(pattern)

    def preprocess(self) -> None:
        self._regex = re.compile(b'|'.join(map(re.escape, self._pattern_strings)))

    def search(self, haystack: bytes) \
            -> Generator[Tuple[int, Union[str, bytes]], None, None]:
        if not isinstance(haystack, bytes):
            raise TypeError("Search haystack must be a byte string")
        for match in re.finditer(self._regex, haystack):
            yield (match.start(0), match.group())


if __name__ == '__main__':
    import multistring_testrig

    multistring_testrig.tester(MultiRegexp())
