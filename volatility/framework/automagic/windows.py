if __name__ == "__main__":
    import os
    import sys

    sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', '..')))

import struct

from volatility.framework import automagic, interfaces, layers, validity
from volatility.framework.configuration import requirements

PAGE_SIZE = 0x1000


class DtbTest(validity.ValidityRoutines):
    super_bit = 2

    def __init__(self, layer_type = None, ptr_struct = None, ptr_reference = None, mask = None):
        self.layer_type = self._check_class(layer_type, interfaces.layers.TranslationLayerInterface)
        self.ptr_struct = self._check_type(ptr_struct, str)
        self.ptr_size = struct.calcsize(ptr_struct)
        self.ptr_reference = self._check_type(ptr_reference, int)
        self.mask = self._check_type(mask, int)

    def unpack(self, value):
        return struct.unpack("<" + self.ptr_struct, value)[0]

    def __call__(self, data, data_offset, page_offset):
        value = data[page_offset + (self.ptr_reference * self.ptr_size):page_offset + (
            (self.ptr_reference + 1) * self.ptr_size)]
        ptr = self.unpack(value)
        # The value *must* be present (bit 0) since it's a mapped page
        # It's almost always writable (bit 1)
        # It's occasionally Super, but not reliably so, haven't checked when/why not
        # The top 3-bits are usually ignore (which in practice means 0
        # Need to find out why the middle 3-bits are usually 6 (0110)
        if ptr != 0 and (ptr & self.mask == data_offset + page_offset) & (ptr & 0xFF1 == 0x61):
            dtb = (ptr & self.mask)
            return self.second_pass(dtb, data, data_offset)

    def second_pass(self, dtb, data, data_offset):
        page = data[dtb - data_offset:dtb - data_offset + PAGE_SIZE]
        usr_count, sup_count = 0, 0
        for i in range(0, PAGE_SIZE, self.ptr_size):
            val = self.unpack(page[i:i + self.ptr_size])
            if val & 0x1:
                sup_count += 0 if (val & 0x4) else 1
                usr_count += 1 if (val & 0x4) else 0
        # print(hex(dtb), usr_count, sup_count, usr_count + sup_count)
        # We sometimes find bogus DTBs at 0x16000 with a very low sup_count and 0 usr_count
        # I have a winxpsp2-x64 image with identical usr/sup counts at 0x16000 and 0x24c00 as well as the actual 0x3c3000
        if usr_count or sup_count > 5:
            return dtb


class DtbTest32bit(DtbTest):
    def __init__(self):
        super().__init__(layer_type = layers.intel.Intel,
                         ptr_struct = "I",
                         ptr_reference = 0x300,
                         mask = 0xFFFFF000)


class DtbTest64bit(DtbTest):
    def __init__(self):
        super().__init__(layer_type = layers.intel.Intel32e,
                         ptr_struct = "Q",
                         ptr_reference = 0x1ED,
                         mask = 0x3FFFFFFFFFF000)


class DtbTestPae(DtbTest):
    def __init__(self):
        super().__init__(layer_type = layers.intel.IntelPAE,
                         ptr_struct = "Q",
                         ptr_reference = 0x3,
                         mask = 0x3FFFFFFFFFF000)

    def second_pass(self, dtb, data, data_offset):
        dtb -= 0x4000
        # If we're not in something that the overlap would pick up
        if dtb - data_offset >= 0:
            pointers = data[dtb - data_offset + (3 * self.ptr_size): dtb - data_offset + (4 * self.ptr_size)]
            val = self.unpack(pointers)
            if (val & self.mask == dtb + 0x4000) and (val & 0xFFF == 0x001):
                return dtb


class DtbSelfReferential(DtbTest):
    def __init__(self, layer_type, ptr_struct, ptr_reference, mask):
        super().__init__(layer_type = layer_type,
                         ptr_struct = ptr_struct,
                         ptr_reference = ptr_reference,
                         mask = mask)

    def __call__(self, data, data_offset, page_offset):
        page = data[page_offset:page_offset + PAGE_SIZE]
        if not page:
            return
        ref_pages = set()
        for ref in range(0, PAGE_SIZE, self.ptr_size):
            ptr_data = page[ref:ref + self.ptr_size]
            if len(ptr_data) == self.ptr_size:
                ptr, = struct.unpack(self.ptr_struct, ptr_data)
                if ((ptr & self.mask) == (data_offset + page_offset)) and (data_offset + page_offset > 0):
                    ref_pages.add(ref)
        if ref_pages:
            return (data_offset + page_offset), ref_pages


class DtbSelfRef32bit(DtbSelfReferential):
    def __init__(self):
        super().__init__(layer_type = layers.intel.Intel, ptr_struct = "I", ptr_reference = 0x300,
                         mask = 0xFFFFF000)


class DtbSelfRef64bit(DtbSelfReferential):
    def __init__(self):
        super().__init__(layer_type = layers.intel.Intel32e, ptr_struct = "Q", ptr_reference = 0x1ED,
                         mask = 0x3FFFFFFFFFF000)


class PageMapScanner(interfaces.layers.ScannerInterface):
    overlap = 0x4000
    tests = [DtbTest32bit, DtbTest64bit, DtbTestPae]

    def __init__(self, tests):
        super().__init__()
        for value in tests:
            self._check_type(value, DtbTest)
        self.tests = tests

    def __call__(self, data, data_offset):
        results = {}
        for test in self.tests:
            results[test] = set()

        for test in self.tests:
            for page_offset in range(0, len(data), PAGE_SIZE):
                result = test(data, data_offset, page_offset)
                if result is not None:
                    yield (test, result)


class PageMapOffsetHelper(interfaces.automagic.AutomagicInterface):
    priority = 20

    def __init__(self):
        super().__init__()
        self.tests = [DtbTest32bit(), DtbTest64bit(), DtbTestPae()]

    def branch_leave(self, node, config_path):
        """Ensure we're called on internal nodes as well as external"""
        self(node, config_path)
        return True

    def __call__(self, context, config_path, requirement):
        useful = []
        sub_config_path = interfaces.configuration.path_join(config_path, requirement.name)
        if isinstance(requirement, requirements.TranslationLayerRequirement):
            class_req = requirement.requirements["class"]
            if not class_req.validate(context, sub_config_path):
                # All the intel spaces require the same kind of parameters, so pick one for the requirements
                context.config.branch(config_path)
                automagic.run(context, layers.intel.Intel,
                              interfaces.configuration.path_join(config_path, requirement.name))

                # If a class hasn't been chosen, look through the underlying config for appropriate parameters
                # If possible run scan and choose an appropriate class
                pass

            for test in self.tests:
                if (test.layer_type.__module__ + "." + test.layer_type.__name__ ==
                        class_req.config_value(context, sub_config_path)):
                    useful.append(test)

            # Determine if a class has been chosen
            # Once an appropriate class has been chosen, attempt to determine the page_map_offset value
            if ("memory_layer" in requirement.requirements and
                    requirement.requirements["memory_layer"].validate(context, sub_config_path)):
                physical_layer = requirement.requirements["memory_layer"].config_value(context, sub_config_path)
                # TODO: Convert to scanner framework
                hits = context.memory[physical_layer].scan(context, PageMapScanner(useful))
                for test, dtb in hits:
                    context.config[interfaces.configuration.path_join(sub_config_path, "page_map_offset")] = dtb
                    requirement.construct(context, config_path)
                    break
        else:
            for subreq in requirement.requirements.values():
                self(context, sub_config_path, subreq)


if __name__ == '__main__':
    import argparse

    from volatility.framework.symbols import native
    from volatility.framework import contexts

    parser = argparse.ArgumentParser()
    parser.add_argument("filenames", metavar = "FILE", nargs = "+", action = "store", help = "FILE to read for testing")
    parser.add_argument("--32bit", action = "store_false", dest = "bit32", help = "Disable 32-bit run")
    parser.add_argument("--64bit", action = "store_false", dest = "bit64", help = "Disable 64-bit run")
    parser.add_argument("--pae", action = "store_false", help = "Disable pae run")

    args = parser.parse_args()

    nativelst = native.x86NativeTable
    ctx = contexts.Context(nativelst)
    for filename in args.filenames:
        data = layers.physical.FileLayer(ctx,
                                         'config' + str(args.filenames.index(filename)),
                                         'data' + str(args.filenames.index(filename)),
                                         filename = filename)
        ctx.memory.add_layer(data)

    tests = []
    if args.bit32:
        tests.append(DtbTest32bit())
    if args.bit64:
        tests.append(DtbTest64bit())
    if args.pae:
        tests.append(DtbTestPae())

    if tests:
        for i in range(len(args.filenames)):
            print("[*] Scanning " + args.filenames[i] + "...")
            guesses = dict([(test.layer_type.__name__, set()) for test in tests])
            hits = ctx.memory["data" + str(i)].scan(ctx, PageMapScanner(tests))
            for test, dtb in sorted(hits):
                guesses[test.layer_type.__name__].add(dtb)
            arch = None
            for guess in sorted(guesses, key = lambda x: -len(guesses[x])):
                if not arch and len(guesses[guess]) > 0:
                    arch = guess
                print("    " + guess + ": " + ", ".join([hex(x) for x in sorted(guesses[guess])]))
            if arch:
                print("[!] OS Guess:", arch, "with DTB", hex(list(guesses[arch])[0]))
            else:
                print("[X] No DTBs found")
            print()
    else:
        print("[X] No tests selected")
