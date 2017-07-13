import re

from volatility.framework.interfaces import layers
from volatility.framework.layers.scanners import pyahocorasick
from volatility.framework.layers.scanners.suffix_tree import SuffixTree


class BytesScanner(layers.ScannerInterface):
    thread_safe = True

    def __init__(self, needle):
        super().__init__()
        self.needle = self._check_type(needle, bytes)

    def __call__(self, data, data_offset):
        """Runs through the data looking for the needle, and yields all offsets where the needle is found
        """
        find_pos = data.find(self.needle)
        while find_pos >= 0:
            yield find_pos + data_offset
            find_pos = data.find(self.needle, find_pos + 1)


class RegExScanner(layers.ScannerInterface):
    # TODO: Document why this isn't thread safe?
    thread_safe = False

    def __init__(self, pattern, flags = 0):
        super().__init__()
        self.regex = re.compile(self._check_type(pattern, bytes), self._check_type(flags, int))

    def __call__(self, data, data_offset):
        """Runs through the data looking for the needle, and yields all offsets where the needle is found
        """
        find_pos = self.regex.finditer(data)
        find_pos = list(find_pos)
        for match in find_pos:
            offset = match.start()
            yield offset + data_offset
