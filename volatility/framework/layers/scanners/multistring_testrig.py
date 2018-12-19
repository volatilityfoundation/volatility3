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


def tester(searcher):
    import argparse

    parser = argparse.ArgumentParser(usage = "Searches through a haystack for a set of needles")
    parser.add_argument(
        "-n", "--needles", help = "The filename of the file containing newline separated needles", required = True)
    parser.add_argument("haystack", help = "The filename of the binary haystack file to search")
    args = parser.parse_args()

    with open(args.needles, "rb") as needles_fp:
        needles = needles_fp.read().split(b"\n")
    with open(args.haystack, "rb") as haystack_fp:
        haystack = haystack_fp.read()
    for needle in needles:
        if len(needle):
            searcher.add_pattern(needle)
    searcher.preprocess()
    for result in searcher.search(haystack):
        print("0x{:x} - {}".format(*result))
