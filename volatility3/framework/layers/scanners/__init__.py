# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
import re
from typing import Generator, List, Tuple, Dict, Optional

from volatility3.framework.interfaces import layers
from volatility3.framework.layers.scanners import multiregexp as multiregexp


class BytesScanner(layers.ScannerInterface):
    thread_safe = True

    _version = (1, 0, 0)

    _required_framework_version = (2, 0, 0)

    def __init__(self, needle: bytes) -> None:
        super().__init__()
        self.needle = needle

    def __call__(self, data: bytes, data_offset: int) -> Generator[int, None, None]:
        """Runs through the data looking for the needle, and yields all offsets
        where the needle is found."""
        find_pos = data.find(self.needle)
        while find_pos >= 0:
            # Ensure that if we're in the overlap, we don't report it
            # It'll be returned when the next block is scanned
            if find_pos < self.chunk_size:
                yield find_pos + data_offset
            find_pos = data.find(self.needle, find_pos + 1)


class RegExScanner(layers.ScannerInterface):
    """A scanner that can be provided with a bytes-object regular expression pattern
    The scanner will scan all blocks for the regular expression and report the absolute offset of any finds

    The default flags include DOTALL, since the searches are through binary data and the newline character should
    have no specific significance in such searches"""

    thread_safe = True

    _version = (1, 0, 0)

    _required_framework_version = (2, 0, 0)

    def __init__(self, pattern: bytes, flags: int = re.DOTALL) -> None:
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

    _version = (1, 0, 0)
    _required_framework_version = (2, 0, 0)

    def __init__(self, patterns: List[bytes]) -> None:
        super().__init__()
        self._pattern_trie: Optional[Dict[int, Optional[Dict]]] = {}
        for pattern in patterns:
            self._process_pattern(pattern)
        self._regex = self._process_trie(self._pattern_trie)

    def _process_pattern(self, value: bytes) -> None:
        trie = self._pattern_trie
        if trie is None:
            return None

        for char in value:
            trie.setdefault(char, {})
            trie = trie[char]

        # Mark the end of a string
        trie[-1] = None

    def _process_trie(self, trie: Optional[Dict[int, Optional[Dict]]]) -> bytes:
        if trie is None or len(trie) == 1 and -1 in trie:
            # We've reached the end of this path, return the empty byte string
            return b""

        choices = []
        suffixes = []
        finished = False

        for entry in sorted(trie):
            # Clump together different paths
            if entry >= 0:
                remainder = self._process_trie(trie[entry])
                if remainder:
                    choices.append(re.escape(bytes([entry])) + remainder)
                else:
                    suffixes.append(re.escape(bytes([entry])))
            else:
                # If we've finished one of the strings at this point, remember it for later
                finished = True

        if len(suffixes) == 1:
            choices.append(suffixes[0])
        elif len(suffixes) > 1:
            choices.append(b"[" + b"".join(suffixes) + b"]")

        if len(choices) == 0:
            # If there's none, return the empty byte string
            response = b""
        elif len(choices) == 1:
            # If there's only one return it
            response = choices[0]
        else:
            response = b"(?:" + b"|".join(choices) + b")"

        if finished:
            # We finished one string, so everything after this is optional
            response = b"(?:" + response + b")?"

        return response

    def __call__(
        self, data: bytes, data_offset: int
    ) -> Generator[Tuple[int, bytes], None, None]:
        """Runs through the data looking for the needles."""
        for offset, pattern in self.search(data):
            if offset < self.chunk_size:
                yield offset + data_offset, pattern

    def search(self, haystack: bytes) -> Generator[Tuple[int, bytes], None, None]:
        if not isinstance(haystack, bytes):
            raise TypeError("Search haystack must be a byte string")
        if not self._regex:
            raise ValueError(
                "MultiRegexp cannot be used with an empty set of search strings"
            )
        for match in re.finditer(self._regex, haystack):
            yield match.start(0), match.group()
