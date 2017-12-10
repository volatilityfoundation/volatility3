import typing


class WuManber(object):
    """Algorithm for multi-string matching"""

    def __init__(self, block_size: int = 3) -> None:
        self.minimum_pattern_length = None  # type: typing.Optional[int]

        self._block_size = block_size
        self._maximum_hash = self._hash_function(b"\xff\xff\xff") + 1  # This depends on the hash function used

        self._patterns = []  # type: typing.List[bytes]
        self._shift = None  # type: typing.Optional[typing.List[int]]
        self._hashes = [set() for _ in range(self._maximum_hash)]  # type: typing.List[typing.Set[bytes]]

    def add_pattern(self, pattern: bytes) -> None:
        if not isinstance(pattern, bytes):
            raise TypeError("Pattern must be a byte string")

        if len(pattern) < self._block_size:
            raise ValueError("Pattern legnth is too short")

        self._patterns.append(pattern)

    def preprocess(self) -> None:
        """Preprocesses the patterns by populating the three arrays"""

        if not self._patterns:
            raise ValueError("No Linux symbols/banner patterns available")

        # Set the minimun pattern length
        self.minimum_pattern_length = min([len(pattern) for pattern in self._patterns])

        max_jump = self.minimum_pattern_length - self._block_size + 1
        self._shift = [max_jump] * self._maximum_hash
        self.hashes = [set() for _ in range(self._maximum_hash)]  # type: typing.List[typing.Set[bytes]]

        for pattern in self._patterns:
            for i in range(self._block_size, self.minimum_pattern_length + 1):
                hashval = self._hash_function(pattern[i - self._block_size:i])
                self._shift[hashval] = min(self._shift[hashval], self.minimum_pattern_length - i)
                # This will be left with the last
                if self.minimum_pattern_length - i == 0:
                    self._hashes[hashval].add(pattern)

    def _hash_function(self, value_bytes: bytes) -> int:
        """Hash function to bucket _block_size number of bytes into sets

        If this hash_function changes, the maximum number of responses must be set in self._maximum_hash
        """
        return (value_bytes[0] << 5) + (value_bytes[1] << 3) + value_bytes[2]

    def search(self, haystack: bytes) \
            -> typing.Generator[typing.Tuple[int, typing.Union[str, bytes]], None, None]:
        """Search through a large body of data for patterns previously added with add_pattern"""
        if not isinstance(haystack, bytes):
            raise TypeError("Search haystack must be a byte string")
        if self._shift is None:
            raise KeyError("Preprocess has not been run on WuManber object yet")
        index = self.minimum_pattern_length
        while index < len(haystack):
            hashval = self._hash_function(haystack[index - self._block_size:index])
            shift = self._shift[hashval]
            if shift < 1:
                shift = 1
                for pattern in self._hashes[hashval]:
                    match_start = index - self.minimum_pattern_length
                    if pattern == haystack[match_start:match_start + len(pattern)]:
                        yield (match_start, pattern)
            index += shift


if __name__ == '__main__':
    wm = WuManber()
    print("Preprocessing")
    for word in [b"quick bro", b"lazy do", b"abcd", b"fgh"]:
        wm.add_pattern(word)
    wm.preprocess()
    print("Preprocessed")
    print("Quick fox")
    for result in wm.search(b"the quick brown fox jumped over the lazy dog"):
        print("RESULT", repr(result))
    print("ABC")
    for result in wm.search(b"abcdefghijk"):
        print("RESULT", repr(result))
