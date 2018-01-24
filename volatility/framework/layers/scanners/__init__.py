import re
import typing

from volatility.framework.interfaces import layers
from volatility.framework.layers.scanners import multiregexp


class BytesScanner(layers.ScannerInterface):
    thread_safe = True

    def __init__(self, needle: bytes) -> None:
        super().__init__()
        self.needle = self._check_type(needle, bytes)

    def __call__(self, data: bytes, data_offset: int) -> typing.Generator[int, None, None]:
        """Runs through the data looking for the needle, and yields all offsets where the needle is found
        """
        find_pos = data.find(self.needle)
        while find_pos >= 0:
            yield find_pos + data_offset
            find_pos = data.find(self.needle, find_pos + 1)


class RegExScanner(layers.ScannerInterface):
    # TODO: Document why this isn't thread safe?
    thread_safe = False

    def __init__(self, pattern: bytes, flags: int = 0) -> None:
        super().__init__()
        self.regex = re.compile(self._check_type(pattern, bytes), self._check_type(flags, int))

    def __call__(self, data: bytes, data_offset: int) -> typing.Generator[int, None, None]:
        """Runs through the data looking for the needle, and yields all offsets where the needle is found
        """
        find_pos = self.regex.finditer(data)
        for match in find_pos:
            offset = match.start()
            yield offset + data_offset


class MultiStringScanner(layers.ScannerInterface):
    thread_safe = True

    def __init__(self, patterns: typing.List[bytes]) -> None:
        super().__init__()
        self._check_type(patterns, list)
        self._patterns = multiregexp.MultiRegexp()
        for pattern in patterns:
            self._check_type(pattern, bytes)
            self._patterns.add_pattern(pattern)
        self._patterns.preprocess()

    def __call__(self, data: bytes, data_offset: int) \
            -> typing.Generator[typing.Tuple[int, typing.Union[str, bytes]], None, None]:
        """Runs through the data looking for the needles"""
        for offset, pattern in self._patterns.search(data):
            yield offset + data_offset, pattern
