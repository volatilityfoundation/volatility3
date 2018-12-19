# This file was contributed to the Volatility Framework Version 3.
# Copyright (C) 2018 Volatility Foundation.
#
# THE LICENSED WORK IS PROVIDED UNDER THE TERMS OF THE Volatility Contributors
# Public License V1.0("LICENSE") AS FIRST COMPLETED BY: Volatility Foundation,
# Inc. ANY USE, PUBLIC DISPLAY, PUBLIC PERFORMANCE, REPRODUCTION OR DISTRIBUTION
# OF, OR PREPARATION OF SUBSEQUENT WORKS, DERIVATIVE WORKS OR DERIVED WORKS BASED
# ON, THE LICENSED WORK CONSTITUTES RECIPIENT'S ACCEPTANCE OF THIS LICENSE AND ITS
# TERMS, WHETHER OR NOT SUCH RECIPIENT READS THE TERMS OF THE LICENSE. "LICENSED
# WORK,” “RECIPIENT" AND “DISTRIBUTOR" ARE DEFINED IN THE LICENSE. A COPY OF THE
# LICENSE IS LOCATED IN THE TEXT FILE ENTITLED "LICENSE.txt" ACCOMPANYING THE
# CONTENTS OF THIS FILE. IF A COPY OF THE LICENSE DOES NOT ACCOMPANY THIS FILE, A
# COPY OF THE LICENSE MAY ALSO BE OBTAINED AT THE FOLLOWING WEB SITE:
# https://www.volatilityfoundation.org/license/vcpl_v1.0
#
# Software distributed under the License is distributed on an "AS IS" basis,
# WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License for the
# specific language governing rights and limitations under the License.
#

from typing import Generator, List, Optional, Set, Tuple, Union


class WuManber(object):
    """Algorithm for multi-string matching"""

    def __init__(self, block_size: int = 3) -> None:
        # Set a suitably large minimum
        self.minimum_pattern_length = 1000000000000

        self._block_size = block_size
        self._maximum_hash = self._hash_function(b"\xff\xff\xff") + 1  # This depends on the hash function used

        self._patterns = []  # type: List[bytes]
        self._shift = None  # type: Optional[List[int]]
        self._hashes = [set() for _ in range(self._maximum_hash)]  # type: List[Set[bytes]]

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
        self.hashes = [set() for _ in range(self._maximum_hash)]  # type: List[Set[bytes]]

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
            -> Generator[Tuple[int, Union[str, bytes]], None, None]:
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
    import multistring_testrig

    multistring_testrig.tester(WuManber())
