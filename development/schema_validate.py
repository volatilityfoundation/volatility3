import argparse
import json
import os

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
