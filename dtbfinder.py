import binascii
import struct
import sys

import volatility.framework
from volatility.framework import layers
from volatility.framework.symbols import native

__author__ = 'mike'

PAGE_SIZE = 0x1000
POINTER_SIZE = 8
STRUCT = "Q"
BIT = 64


def utils_load_as():
    nativelst = native.x86NativeTable

    #    virtual_types = xp_sp2_x86_vtypes.ntkrnlmp_types
    #
    #    ntkrnlmp = vtypes.VTypeSymbolTable('ntkrnlmp', virtual_types, nativelst)

    ctx = volatility.framework.contexts.Context(nativelst)
    # ctx.symbol_space.append(nativelst)
    # ctx.symbol_space.append(ntkrnlmp)
    return ctx


class DTBFinderX64(object):
    def __init__(self, ctx):
        self.ctx = ctx
        self.page_map = {}

    def store_page_mappings(self, offset):
        page = self.ctx.memory.read('data', offset, PAGE_SIZE)
        self.page_map[offset] = [x & 0xFFFFFFFFFFFFF000 for x in
                                 struct.unpack("<" + STRUCT * int(PAGE_SIZE / POINTER_SIZE), page) if (x & 1 == 1)]

    def scan(self, magic = 0x1ED):
        for offset in range(self.ctx.memory['data'].minimum_address, self.ctx.memory['data'].maximum_address,
                            PAGE_SIZE):
            null = struct.unpack("<" + STRUCT, self.ctx.memory.read('data', offset, POINTER_SIZE))[0]
            val = self.ctx.memory.read('data', offset + (magic * POINTER_SIZE), POINTER_SIZE)
            test_val = struct.unpack("<" + STRUCT, val)[0] & 0xFFFFFFFFFFFFF000
            offsetstr = ("{0:#0" + str((POINTER_SIZE * 2) + 2) + "x}").format(offset)
            testvalstr = ("{0:#0" + str((POINTER_SIZE * 2) + 2) + "x}").format(test_val)
            if offset == test_val and offset != 0:
                self.store_page_mappings(offset)
                print("MATCH at", offsetstr, "with magic", magic, "null", null)
                # print("Offset", offsetstr, "Value", testvalstr)

        # print(repr(self.page_map))
        self.process_page_map()

    def process_page_map(self):
        for offset in self.page_map:

            # Read through each of the entries to see how close it is to the actual DTB
            bitmap = ""
            for index in range(0, PAGE_SIZE, POINTER_SIZE):
                val = self.ctx.memory.read('data', offset + index, POINTER_SIZE)
                correct_val = self.ctx.memory.read('data', 0x0000000000124000 + index, POINTER_SIZE)
                if val == 0:
                    bitmap += "."
                else:
                    bitmap += ("1" if val == correct_val else "0")
            print("{0:#018x}".format(offset), bitmap, "\n")

            # if offset == 0x00000000003c3000:
            # if offset == 0x0000000000124000:
            #                print(sorted("{0:#018x}".format(x) for x in self.page_map[offset] if x != 0))
            #                print(sorted("{0:#018x}".format(x) for x in self.page_map.keys() if x != 0))
            #                break
            # for value in self.page_map[index]:
            # if value in self.page_map.keys():
            #        counts["{0:#018x}".format(value)] = counts.get("{0:#018x}".format(value), 0) + 1


def display_dtb(ctx, dtb_offset):
    data = ctx.memory['data'].read(dtb_offset, PAGE_SIZE)
    for index in range(int(PAGE_SIZE / POINTER_SIZE)):
        value = data[index * POINTER_SIZE:(index + 1) * POINTER_SIZE]
        if binascii.hexlify(value) != b"0000000000000000":
            print("Index", index, "Value", binascii.hexlify(value))


if __name__ == '__main__':

    if BIT == 32:
        POINTER_SIZE = 4
        STRUCT = "I"

    ctx = utils_load_as()
    data = layers.physical.FileLayer(ctx, 'name', 'data', filename = sys.argv[1])
    ctx.memory.add_layer(data)
    # display_dtb(ctx, int(sys.argv[2], 16))
    DTBFinderX64(ctx).scan()
