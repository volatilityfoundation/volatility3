import argparse
import json
import logging
import os
import sys

# TODO: Rather nasty hack, when volatility's actually installed this would be unnecessary
sys.path += ".."

console = logging.StreamHandler()
console.setLevel(logging.DEBUG)
formatter = logging.Formatter("%(levelname)-8s %(name)-12s: %(message)s")
console.setFormatter(formatter)

logger = logging.getLogger("")
logger.addHandler(console)
logger.setLevel(logging.DEBUG)

from volatility3 import schemas  # noqa: E402

if __name__ == "__main__":
    parser = argparse.ArgumentParser("Validates ")
    parser.add_argument("-s", "--schema", dest="schema", default=None)
    parser.add_argument("filenames", metavar="FILE", nargs="+")

    args = parser.parse_args()

    schema = None
    if args.schema:
        with open(os.path.abspath(args.schema)) as s:
            schema = json.load(s)

    failures = []
    for filename in args.filenames:
        try:
            if os.path.exists(filename):
                print(f"[?] Validating file: {filename}")
                with open(filename) as t:
                    test = json.load(t)

                if args.schema:
                    result = schemas.valid(test, schema, False)
                else:
                    result = schemas.validate(test, False)

                if result:
                    print(f"[+] Validation successful: {filename}")
                else:
                    print(f"[-] Validation failed: {filename}")
                    failures.append(filename)
            else:
                print(f"[x] File not found: {filename}")
        except Exception as e:
            failures.append(filename)
            print(f"[x] Exception occurred: {filename} ({repr(e)})")

    print("Failures", failures)
