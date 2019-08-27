# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl_v1.0
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
