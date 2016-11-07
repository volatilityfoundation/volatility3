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

from volatility import schemas

if __name__ == '__main__':
    parser = argparse.ArgumentParser("Validates ")
    parser.add_argument("-s", "--schema", dest = "schema", default = None)
    parser.add_argument("filenames", metavar = "FILE", nargs = '+')

    args = parser.parse_args()

    schema = None
    if args.schema:
        basepath = os.path.abspath(os.path.dirname(__file__))
        with open(os.path.join(basepath, args.schema), 'r') as s:
            schema = json.load(s)
    for filename in args.filenames:
        if os.path.exists(filename):
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
        else:
            print("[x] File not found: {}".format(filename))
