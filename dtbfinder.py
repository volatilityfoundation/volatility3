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
    super_bit = 2

    def unpack(self, value):
        return struct.unpack("<" + self.ptr_struct, value)[0]

    def run(self, page_offset, ctx):
        value = ctx.memory.read('data', page_offset + (self.ptr_reference * self.ptr_size),
                                self.ptr_size)
        ptr = self.unpack(value)
        # The value *must* be present (bit 0) since it's a mapped page
        # It's almost always writable (bit 1)
        # It's occasionally Super, but not reliably so, haven't checked when/why not
        # The top 3-bits are usually ignore (which in practice means 0
        # Need to find out why the middle 3-bits are usually 6 (0110)
        if ptr != 0 and (ptr & 0xFFFFFFFFFFFFF000 == page_offset) & (ptr & 0xFF1 == 0x61):
            dtb = (ptr & 0xFFFFFFFFFFFFF000)
            return self.second_pass(dtb, ctx)

    def second_pass(self, dtb, ctx):
        data = ctx.memory.read("data", dtb, PAGE_SIZE)
        usr_count, sup_count = 0, 0
        for i in range(0, PAGE_SIZE, self.ptr_size):
            val = self.unpack(data[i:i + self.ptr_size])
            if val & 0x1:
                sup_count += 0 if (val & 0x4) else 1
                usr_count += 1 if (val & 0x4) else 0
        # print(hex(dtb), usr_count, sup_count, usr_count + sup_count)
        if usr_count:
            return usr_count, dtb


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

    def second_pass(self, dtb, ctx):
        dtb -= 0x4000
        data = ctx.memory.read("data", dtb, PAGE_SIZE)
        val = self.unpack(data[3 * self.ptr_size: 4 * self.ptr_size])
        if (val & 0xFFFFFFFFFFFFF000 == dtb + 0x4000) and (val & 0xFFF == 0x001):
            return val, dtb


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
                val = test.run(offset, self.ctx)
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
    for key in tests:
        hits = df.hits.get(key.name, [])
        if hits:
            print(key.name + ": " + hex(min(hits)[1]))
    print("[*] OS Guess")
    guesses = []
    for key in df.hits:
        guesses.append((len(df.hits[key]), key))
    print(max(guesses)[1])
