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

import re
from typing import Generator, List, Tuple, Union

from volatility.framework.interfaces import layers
from volatility.framework.layers.scanners import multiregexp


class BytesScanner(layers.ScannerInterface):
    thread_safe = True

    def __init__(self, needle: bytes) -> None:
        super().__init__()
        self.needle = needle

    def __call__(self, data: bytes, data_offset: int) -> Generator[int, None, None]:
        """Runs through the data looking for the needle, and yields all offsets where the needle is found
        """
        find_pos = data.find(self.needle)
        while find_pos >= 0:
            if find_pos < self.chunk_size:
                yield find_pos + data_offset
            find_pos = data.find(self.needle, find_pos + 1)


class RegExScanner(layers.ScannerInterface):
    # TODO: Document why this isn't thread safe?
    thread_safe = False

    def __init__(self, pattern: bytes, flags: int = 0) -> None:
        super().__init__()
        self.regex = re.compile(pattern, flags)

    def __call__(self, data: bytes, data_offset: int) -> Generator[int, None, None]:
        """Runs through the data looking for the needle, and yields all offsets where the needle is found
        """
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

    def __call__(self, data: bytes, data_offset: int) -> Generator[Tuple[int, Union[str, bytes]], None, None]:
        """Runs through the data looking for the needles"""
        for offset, pattern in self._patterns.search(data):
            if offset < self.chunk_size:
                yield offset + data_offset, pattern
