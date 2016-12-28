"""Module to identify the Directory Table Base and architecture of windows memory images

This module contains a PageMapScanner that scans a physical layer to identify self-referential pointers.
All windows versions include a self-referential pointer in their Directory Table Base's top table, in order to
have a single offset that will allow manipulation of the page tables themselves.

In older windows version the self-referential pointer was at a specific fixed index within the table,
which was different for each architecture.  In very recent Windows versions, the self-referential pointer
index has been randomized, so a different heuristic must be used.  In these versions of windows it was found
that the physical offset for the DTB was always within the range of 0x1a0000 to 0x1b0000.  As such, a search
for any self-referential pointer within these pages gives a high probability of being an accurate DTB.

The self-referential indices for older versions of windows are listed below:

    +--------------+-------+
    | Architecture | Index |
    +==============+=======+
    | x86          | 0x300 |
    +--------------+-------+
    | PAE          | 0x3   |
    +--------------+-------+
    | x64          | 0x1ED |
    +--------------+-------+
"""
import logging
import struct

from volatility.framework import interfaces, layers, validity
from volatility.framework.configuration import requirements

vollog = logging.getLogger(__name__)

PAGE_SIZE = 0x1000


class DtbTest(validity.ValidityRoutines):
    """This class generically contains the tests for a page based on a set of class parameters

    When constructed it contains all the information necessary to extract a specific index from a page
    and determine whether it points back to that page's offset.
    """

    def __init__(self, layer_type = None, ptr_struct = None, ptr_reference = None, mask = None):
        self.layer_type = self._check_class(layer_type, interfaces.layers.TranslationLayerInterface)
        self.ptr_struct = self._check_type(ptr_struct, str)
        self.ptr_size = struct.calcsize(ptr_struct)
        self.ptr_reference = self._check_type(ptr_reference, int)
        self.mask = self._check_type(mask, int)

    def _unpack(self, value):
        return struct.unpack("<" + self.ptr_struct, value)[0]

    def __call__(self, data, data_offset, page_offset):
        """Tests a specific page in a chunk of data to see if it contains a self-referential pointer.

        :param data: The chunk of data that contains the page to be scanned
        :type data: bytes
        :param data_offset: Where, within the layer, the chunk of data lives
        :type data_offset: int
        :param page_offset: Where, within the data, the page to be scanned starts
        :type page_offset: int
        :return: A valid DTB within this page
        """
        value = data[page_offset + (self.ptr_reference * self.ptr_size):page_offset + (
            (self.ptr_reference + 1) * self.ptr_size)]
        ptr = self._unpack(value)
        # The value *must* be present (bit 0) since it's a mapped page
        # It's almost always writable (bit 1)
        # It's occasionally Super, but not reliably so, haven't checked when/why not
        # The top 3-bits are usually ignore (which in practice means 0
        # Need to find out why the middle 3-bits are usually 6 (0110)
        if ptr != 0 and (ptr & self.mask == data_offset + page_offset) & (ptr & 0xFF1 == 0x61):
            dtb = (ptr & self.mask)
            return self.second_pass(dtb, data, data_offset)

    def second_pass(self, dtb, data, data_offset):
        """Re-reads over the whole page to validate other records based on the number of pages marked user vs super

        :param dtb: The identified dtb that needs validating
        :type dtb: int
        :param data: The chunk of data that contains the dtb to be validated
        :type data: bytes
        :param data_offset: Where, within the layer, the chunk of data lives
        :type data_offset: int
        :return: A valid DTB within this page
        """
        page = data[dtb - data_offset:dtb - data_offset + PAGE_SIZE]
        usr_count, sup_count = 0, 0
        for i in range(0, PAGE_SIZE, self.ptr_size):
            val = self._unpack(page[i:i + self.ptr_size])
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
        """PAE top level directory tables contains four entries and the self-referential pointer occurs in the second
        level of tables (so as not to use up a full quarter of the space).  This is very high in the space, and occurs
        in the fourht (last quarter) second-level table.  The second-level tables appear always to come sequentially
        directly after the real dtb.  The value for the real DTB is therefore four page earlier (and the fourth entry
        should point back to the `dtb` parameter this function was originally passed.

        :param dtb: The identified self-referential pointer that needs validating
        :type dtb: int
        :param data: The chunk of data that contains the dtb to be validated
        :type data: bytes
        :param data_offset: Where, within the layer, the chunk of data lives
        :type data_offset: int
        :return: Returns the actual DTB of the PAE space
        :rtype: int
        """
        dtb -= 0x4000
        # If we're not in something that the overlap would pick up
        if dtb - data_offset >= 0:
            pointers = data[dtb - data_offset + (3 * self.ptr_size): dtb - data_offset + (4 * self.ptr_size)]
            val = self._unpack(pointers)
            if (val & self.mask == dtb + 0x4000) and (val & 0xFFF == 0x001):
                return dtb


class DtbSelfReferential(DtbTest):
    """A generic DTB test which looks for a self-referential pointer at *any* index within the page."""

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
        # The DTB is extremely unlikely to refer back to itself. so the number of reference should always be exactly 1
        if len(ref_pages) == 1:
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
    """Scans through all pages using DTB tests to determine a dtb offset and architecture"""
    overlap = 0x4000
    thread_safe = True
    tests = [DtbTest32bit, DtbTest64bit, DtbTestPae]
    """The default tests to run when searching for DTBs"""

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


class WintelHelper(interfaces.automagic.AutomagicInterface, interfaces.automagic.StackerLayerInterface):
    """This class if both an :class:`~volatility.framework.interfaces.automagic.AutomagicInterface` and a
    :class:`~volatility.framework.interfaces.automagic.StackerLayerInterface` class.

    It will both scan for existing TranslationLayers that do not have a DTB and scan for them using
    the :class:`PageMapScanner`, and also act as a stacker when a
    :class:`~volatility.framework.interfaces.configuration.TranslationLayerRequirement` has not been fulfilled"""
    priority = 20
    stack_order = 90
    tests = [DtbTest32bit(), DtbTest64bit(), DtbTestPae()]

    def __call__(self, context, config_path, requirement, progress_callback = None):
        useful = []
        sub_config_path = interfaces.configuration.path_join(config_path, requirement.name)
        if (isinstance(requirement, requirements.TranslationLayerRequirement) and
                requirement.requirements.get("class", None)):
            class_req = requirement.requirements["class"]

            for test in self.tests:
                if (test.layer_type.__module__ + "." + test.layer_type.__name__ ==
                        class_req.config_value(context, sub_config_path)):
                    useful.append(test)

            # Determine if a class has been chosen
            # Once an appropriate class has been chosen, attempt to determine the page_map_offset value
            if ("memory_layer" in requirement.requirements and
                    requirement.requirements["memory_layer"].validate(context, sub_config_path)):
                physical_layer = requirement.requirements["memory_layer"].config_value(context, sub_config_path)
                hits = context.memory[physical_layer].scan(context, PageMapScanner(useful), progress_callback)
                for test, dtb in hits:
                    context.config[interfaces.configuration.path_join(sub_config_path, "page_map_offset")] = dtb
                    requirement.construct(context, config_path)
                    break
        else:
            for subreq in requirement.requirements.values():
                self(context, sub_config_path, subreq)

    @classmethod
    def stack(cls, context, layer_name, progress_callback = None):
        """Attempts to determine and stack an intel layer on a physical layer where possible

        Where the DTB scan fails, it attempts a heuristic of checking for the DTB within a specific range.
        New versions of windows, with randomized self-referential pointers, appear to always load their dtb within
        a small specific range (`0x1a0000` and `0x1b0000`), so instead we scan for all self-referential pointers in
        that range, and ignore any that contain multiple self-references (since the DTB is very unlikely to point to
        itself more than once).
        """
        hits = context.memory[layer_name].scan(context, PageMapScanner(cls.tests))
        layer = None
        for test, dtb in hits:
            new_layer_name = context.memory.free_layer_name("IntelLayer")
            config_path = interfaces.configuration.path_join("IntelHelper", new_layer_name)
            context.config[interfaces.configuration.path_join(config_path, "memory_layer")] = layer_name
            context.config[interfaces.configuration.path_join(config_path, "page_map_offset")] = dtb
            layer = test.layer_type(context,
                                    config_path = config_path,
                                    name = new_layer_name)
            break
        if layer is None:
            vollog.debug("Self-referential pointer not in well-known location, moving to recent windows heuristic")
            # There is a very high chance that the DTB will live in this narrow segment, assuming we couldn't find it previously
            # TODO: This scan takes time, it might be worth adding a progress callback to it
            hits = context.memory[layer_name].scan(context, PageMapScanner([DtbSelfRef64bit()]), min_address = 0x1a0000,
                                                   max_address = 0x1f0000, progress_callback = progress_callback)
            # Flatten the generator
            hits = list(hits)
            if hits:
                # TODO: Decide which to use if there are multiple options
                page_map_offset = hits[0][1][0]
                new_layer_name = context.memory.free_layer_name("IntelLayer")
                config_path = interfaces.configuration.path_join("IntelHelper", new_layer_name)
                context.config[interfaces.configuration.path_join(config_path, "memory_layer")] = layer_name
                context.config[interfaces.configuration.path_join(config_path, "page_map_offset")] = page_map_offset
                # TODO: Need to determine the layer type (chances are high it's x64, hence this default)
                layer = layers.intel.Intel32e(context, config_path = config_path, name = new_layer_name)
        if layer is not None:
            vollog.debug("DTB was found at: 0x{:0x}".format(
                context.config[interfaces.configuration.path_join(config_path, "page_map_offset")]))
        return layer
