# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

import re
from typing import Generator, List, Tuple

from volatility3.framework.interfaces import layers
from volatility3.framework.layers.scanners import multiregexp


class BytesScanner(layers.ScannerInterface):
    thread_safe = True

    def __init__(self, needle: bytes) -> None:
        super().__init__()
        self.needle = needle

    def __call__(self, data: bytes, data_offset: int) -> Generator[int, None, None]:
        """Runs through the data looking for the needle, and yields all offsets
        where the needle is found."""
        find_pos = data.find(self.needle)
        while find_pos >= 0:
            if find_pos < self.chunk_size:
                yield find_pos + data_offset
            find_pos = data.find(self.needle, find_pos + 1)


class RegExScanner(layers.ScannerInterface):
    thread_safe = True

    def __init__(self, pattern: bytes, flags: int = 0) -> None:
        super().__init__()
        self.regex = re.compile(pattern, flags)

    def __call__(self, data: bytes, data_offset: int) -> Generator[int, None, None]:
        """Runs through the data looking for the needle, and yields all offsets
        where the needle is found."""
        find_pos = self.regex.finditer(data)
        for match in find_pos:
            offset = match.start()
            if offset < self.chunk_size:
                yield offset + data_offset


class MultiStringScanner(layers.ScannerInterface):
    thread_safe = True

    def __init__(self, patterns: List[bytes]) -> None:
        super().__init__()
        self._patterns = multiregexp.MultiRegexp()
        for pattern in patterns:
            self._patterns.add_pattern(pattern)
        self._patterns.preprocess()

    def __call__(self, data: bytes, data_offset: int) -> Generator[Tuple[int, bytes], None, None]:
        """Runs through the data looking for the needles."""
        for offset, pattern in self._patterns.search(data):
            if offset < self.chunk_size:
                yield offset + data_offset, pattern
