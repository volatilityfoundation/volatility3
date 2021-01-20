import argparse
import json
import os
import sys

# TODO: Rather nasty hack, when volatility's actually installed this would be unnecessary
sys.path += ".."

import logging

console = logging.StreamHandler()
console.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(levelname)-8s %(name)-12s: %(message)s')
console.setFormatter(formatter)

logger = logging.getLogger("")
logger.addHandler(console)
logger.setLevel(logging.DEBUG)

from volatility3 import schemas

if __name__ == '__main__':
    parser = argparse.ArgumentParser("Validates ")
    parser.add_argument("-s", "--schema", dest = "schema", default = None)
    parser.add_argument("filenames", metavar = "FILE", nargs = '+')

    args = parser.parse_args()

    schema = None
    if args.schema:
        with open(os.path.abspath(args.schema), 'r') as s:
            schema = json.load(s)

    failures = []
    for filename in args.filenames:
        try:
            if os.path.exists(filename):
                print("[?] Validating file: {}".format(filename))
                with open(filename, 'r') as t:
                    test = json.load(t)

                if args.schema:
                    result = schemas.valid(test, schema, False)
                else:
                    result = schemas.validate(test, False)

                if result:
                    print("[+] Validation successful: {}".format(filename))
                else:
                    print("[-] Validation failed: {}".format(filename))
                    failures.append(filename)
            else:
                print("[x] File not found: {}".format(filename))
        except Exception as e:
            failures.append(filename)
            print("[x] Exception occurred: {} ({})".format(filename, repr(e)))

    print("Failures", failures)
