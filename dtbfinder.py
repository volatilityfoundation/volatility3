import argparse
import struct

import volatility.framework
from volatility.framework import layers
from volatility.framework.symbols import native

__author__ = 'mike'

PAGE_SIZE = 0x1000


def utils_load_as():
    #    virtual_types = xp_sp2_x86_vtypes.ntkrnlmp_types
    #
    #    ntkrnlmp = vtypes.VTypeSymbolTable('ntkrnlmp', virtual_types, nativelst)

    # ctx.symbol_space.append(nativelst)
    # ctx.symbol_space.append(ntkrnlmp)
    return ctx


class DtbTest(object):
    ptr_size = 4
    ptr_struct = "I"
    ptr_reference = 0x300

    def run(self, value, page_offset):
        ptr = struct.unpack("<" + self.ptr_struct, value)[0]
        if ptr != 0 and (ptr & 0xFFFFFFFFFFFFF000 == page_offset) and (ptr & 0xFF0 == 0x60):
            return hex(ptr & 0xFFFFFFFFFFFFF000)


class Test32bit(DtbTest):
    name = "x86 32-bit (Non-PAE)"
    ptr_size = 4
    ptr_struct = "I"
    ptr_reference = 0x300


class Test64bit(DtbTest):
    name = "x64 64-bit"
    ptr_size = 8
    ptr_struct = "Q"
    ptr_reference = 0x1ED


class TestPaebit(DtbTest):
    name = "x86 48-bit (PAE)"
    ptr_size = 8
    ptr_struct = "Q"
    ptr_reference = 0x3


class DTBFinder(object):
    def __init__(self, ctx, tests):
        self.ctx = ctx
        self.page_map = {}
        self.hits = {}
        self.tests = tests

    def scan(self):
        for offset in range(self.ctx.memory['data'].minimum_address,
                            self.ctx.memory['data'].maximum_address - PAGE_SIZE,
                            PAGE_SIZE):
            for test in self.tests:
                val = test.run(
                    self.ctx.memory.read('data', offset + (test.ptr_reference * test.ptr_size), test.ptr_size), offset)
                if val:
                    self.hits[test.name] = self.hits.get(test.name, []) + [val]


if __name__ == '__main__':

    parser = argparse.ArgumentParser()
    parser.add_argument("--32bit", action = "store_false", dest = "bit32", help = "Disable 32-bit run")
    parser.add_argument("--64bit", action = "store_false", dest = "bit64", help = "Disable 64-bit run")
    parser.add_argument("--pae", action = "store_false", help = "Disable pae run")
    parser.add_argument("-f", "--file", metavar = "FILE", action = "store", help = "FILE to read for testing")

    args = parser.parse_args()

    nativelst = native.x86NativeTable
    ctx = volatility.framework.contexts.Context(nativelst)
    data = layers.physical.FileLayer(ctx, 'name', 'data', filename = args.file)
    ctx.memory.add_layer(data)

    tests = []
    if args.bit32:
        tests.append(Test32bit())
    if args.bit64:
        tests.append(Test64bit())
    if args.pae:
        tests.append(TestPaebit())

    df = DTBFinder(ctx, tests)
    print("[*] Scanning...")
    df.scan()
    print("[*] Results")
    print(df.hits)
    print("[*] OS Guess")
    guesses = []
    for key in df.hits:
        guesses.append((len(df.hits[key]), key))
    print(max(guesses)[1])
