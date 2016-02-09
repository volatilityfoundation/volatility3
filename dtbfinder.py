import argparse
import struct

import volatility.framework
from volatility.framework import layers
from volatility.framework.symbols import native

__author__ = 'mike'

PAGE_SIZE = 0x1000


def utils_load_as():
    nativelst = native.x86NativeTable

    #    virtual_types = xp_sp2_x86_vtypes.ntkrnlmp_types
    #
    #    ntkrnlmp = vtypes.VTypeSymbolTable('ntkrnlmp', virtual_types, nativelst)

    ctx = volatility.framework.contexts.Context(nativelst)
    # ctx.symbol_space.append(nativelst)
    # ctx.symbol_space.append(ntkrnlmp)
    return ctx


class DTBFinder(object):
    def __init__(self, ctx):
        self.ctx = ctx
        self.page_map = {}

    def scan(self, pointer_size, pointer_struct, magic):
        for offset in range(self.ctx.memory['data'].minimum_address, self.ctx.memory['data'].maximum_address,
                            PAGE_SIZE):
            null = struct.unpack("<" + pointer_struct, self.ctx.memory.read('data', offset, pointer_size))[0]
            val = self.ctx.memory.read('data', offset + (magic * pointer_size), pointer_size)
            test_val = struct.unpack("<" + pointer_struct, val)[0] & 0xFFFFFFFFFFFFF000
            offsetstr = ("{0:#0" + str((pointer_size * 2) + 2) + "x}").format(offset)
            testvalstr = ("{0:#0" + str((pointer_size * 2) + 2) + "x}").format(test_val)
            if offset == test_val and offset != 0:
                print("MATCH at", offsetstr, "with magic", magic, "null", null)

    def scan32(self):
        self.scan(4, "I", 0x300)

    def scan64(self):
        self.scan(8, "Q", 0x1ED)

    def scanpae(self):
        self.scan(8, "Q", 0x3)


if __name__ == '__main__':

    parser = argparse.ArgumentParser()
    parser.add_argument("--32bit", action = "store_true", dest = "bit32", help = "32-bit tests")
    parser.add_argument("--64bit", action = "store_true", dest = "bit64", help = "64-bit tests")
    parser.add_argument("--pae", action = "store_true", help = "pae tests")
    parser.add_argument("-f", "--file", metavar = "FILE", action = "store", help = "FILE to read for testing")

    args = parser.parse_args()

    ctx = utils_load_as()
    data = layers.physical.FileLayer(ctx, 'name', 'data', filename = args.file)
    ctx.memory.add_layer(data)

    df = DTBFinder(ctx)
    # display_dtb(ctx, int(sys.argv[2], 16))
    if args.bit64:
        print("[*] Start 64-bit scan")
        df.scan64()
    if args.bit32:
        print("[*] Start 32-bit scan")
        df.scan32()
    if args.pae:
        print("[*] Start pae scan")
        df.scanpae()
