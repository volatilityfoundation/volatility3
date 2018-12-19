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
