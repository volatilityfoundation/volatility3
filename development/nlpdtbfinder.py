"""nlpdtbfinder is an OS-agnostic DTB finder for Intel32e 4-layer paging.

It should be extensible to other forms of paging.

Some of the masks used are heuristics, but have been tested against recent
images from OSX, Windows, and Linux.

Adapted from dtbfinder.py.
"""

import sys

# TODO: Remove this once we install volatility
sys.path += ".."

from volatility.framework import contexts
from volatility.framework import interfaces
from volatility.framework import layers
from volatility.framework import exceptions

import struct

PAGE_SIZE = 0x1000
PHYS_MASK = 0xfffffffffff
PML4_ENTRY_SIZE = int((2 ** 64) / 512)


class PML4EScanner(interfaces.layers.ScannerInterface):
    overlap = 0x4000

    def __call__(self, data, data_offset):
        # print("offset: 0x%x len: %d" % (data_offset, len(data)))

        # go through each page in the data, look for signs of PML4
        for page_offset in range(0, len(data), PAGE_SIZE):
            entries = struct.unpack('<512Q', data[page_offset:page_offset + PAGE_SIZE])
            valid_entries = []
            invalid_count = 0
            user_count = 0
            supervisor_count = 0

            entry_num = 0
            for e in entries:
                # print("PML4E: " + bin(e))
                if (e & 0b10111011) == 0b00100011:
                    # print("It's valid!")
                    valid_entries.append((entry_num, e))

                    if (e & 0b100):
                        user_count = user_count + 1
                    else:
                        supervisor_count = supervisor_count + 1

                elif e != 0:
                    invalid_count = invalid_count + 1

                entry_num = entry_num + 1

            # print("[%x] inv: %d val: %d" % (data_offset + page_offset, invalid_count, len(valid_entries)))
            if invalid_count == 0 and len(valid_entries) > 4 and user_count != 0 and supervisor_count != 0:
                if page_offset < self.chunk_size:
                    yield (data_offset + page_offset, valid_entries)


def find_pt_mapping(ctx, layer_name, entries):
    for entry in entries:
        # valid entry?
        # print("pt: " + bin(entry))
        if (entry & 0b1111011) == 0b1100011:
            return True

    return False


def find_pd_mapping(ctx, layer_name, entries):
    for entry in entries:
        # valid entry?
        # print("pd: " + bin(entry))
        if not ((entry & 0b1111011) == 0b1100011):
            continue

        # bit 7 is large page
        if (entry & 0b10000000):
            return True

        pt_offset = (entry & PHYS_MASK) >> 12
        try:
            pt = ctx.memory.read(baselayer_name, pt_offset, PAGE_SIZE)
        except exceptions.InvalidAddressException:
            # print("page fault at " + hex(pt_offset))
            return False

        pt_entries = struct.unpack('<512Q', pt)
        if find_pt_mapping(ctx, layer_name, pt_entries):
            return True
    return False


def find_pdpt_mapping(ctx, layer_name, entries):
    for entry in entries:
        # valid entry?
        # print("pdpte: " + bin(entry))
        if not (entry & 1):
            continue

        # bit 7 is large page
        if (entry & 0b10000000):
            return True

        pd_offset = (entry & PHYS_MASK) >> 12
        try:
            pd = ctx.memory.read(baselayer_name, pd_offset, PAGE_SIZE)
        except exceptions.InvalidAddressException:
            # print("page fault at " + hex(pd_offset))
            return False

        pd_entries = struct.unpack('<512Q', pd)
        if find_pd_mapping(ctx, layer_name, pd_entries):
            return True
    return False


def find_pml4_mapping(ctx, layer_name, entries):
    """Walks through the list of PML4 (idx, entry) entries looking for the
    first valid (and present) mapping"""

    for (idx, entry) in entries:
        # print("PML4E [%d]: %s" % (idx, bin(entry)))
        pdpte_offset = (entry & PHYS_MASK) >> 12

        try:
            pdpte = ctx.memory.read(baselayer_name, pdpte_offset, PAGE_SIZE)
        except exceptions.InvalidAddressException:
            # print("page fault at " + hex(pdpte_offset))
            return False

        pdpte_entries = struct.unpack('<512Q', pdpte)
        if find_pdpt_mapping(ctx, layer_name, pdpte_entries):
            return True

    return False


if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("filenames", metavar = "FILE", nargs = "+", action = "store", help = "FILE to read for testing")
    parser.add_argument("-l", "--lime", action = "store_true", dest = "lime", help = "All files are LIME format")
    parser.add_argument("-v", "--verbose", action = "count", default = 0,
                        help = "Increase the verbosity of the information returned")

    args = parser.parse_args()

    ctx = contexts.Context()
    for filename in args.filenames:
        ctx.config[
            interfaces.configuration.path_join('config' + str(args.filenames.index(filename)), "filename")] = filename
        data = layers.physical.FileLayer(ctx,
                                         'config' + str(args.filenames.index(filename)),
                                         'data' + str(args.filenames.index(filename)))
        ctx.memory.add_layer(data)
        if args.lime:
            ctx.config[interfaces.configuration.path_join('lime-config' + str(args.filenames.index(filename)),
                                                          "base_layer")] = 'data' + str(args.filenames.index(filename))
            data = layers.lime.LimeLayer(ctx,
                                         'lime-config' + str(args.filenames.index(filename)),
                                         'lime-data' + str(args.filenames.index(filename)))
            ctx.memory.add_layer(data)

        layername = 'data'
        if args.lime:
            layername = 'lime-data'

        print(str(ctx.config))

        for i in range(len(args.filenames)):
            print("[*] Scanning " + args.filenames[i] + "...")
            baselayer_name = layername + str(i)
            scan_results = ctx.memory[baselayer_name].scan(ctx, PML4EScanner())

            for (dtb, entries) in scan_results:
                # print("trying: " + hex(dtb))
                if find_pml4_mapping(ctx, baselayer_name, entries):
                    print("[!] %x" % dtb)
            print()
