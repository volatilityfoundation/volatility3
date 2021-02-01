# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
"""Module to identify the Directory Table Base and architecture of windows
memory images.

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
from typing import Any, Generator, List, Optional, Tuple, Type

from volatility3.framework import interfaces, layers, constants
from volatility3.framework.configuration import requirements
from volatility3.framework.layers import intel

vollog = logging.getLogger(__name__)


class DtbTest:
    """This class generically contains the tests for a page based on a set of
    class parameters.

    When constructed it contains all the information necessary to
    extract a specific index from a page and determine whether it points
    back to that page's offset.
    """

    def __init__(self, layer_type: Type[layers.intel.Intel], ptr_struct: str, ptr_reference: int, mask: int) -> None:
        self.layer_type = layer_type
        self.ptr_struct = ptr_struct
        self.ptr_size = struct.calcsize(ptr_struct)
        self.ptr_reference = ptr_reference
        self.mask = mask
        self.page_size = layer_type.page_size  # type: int

    def _unpack(self, value: bytes) -> int:
        return struct.unpack("<" + self.ptr_struct, value)[0]

    def __call__(self, data: bytes, data_offset: int, page_offset: int) -> Optional[Tuple[int, Any]]:
        """Tests a specific page in a chunk of data to see if it contains a
        self-referential pointer.

        Args:
            data: The chunk of data that contains the page to be scanned
            data_offset: Where, within the layer, the chunk of data lives
            page_offset: Where, within the data, the page to be scanned starts

        Returns:
            A valid DTB within this page (and an additional parameter for data)
        """
        value = data[page_offset + (self.ptr_reference * self.ptr_size):page_offset +
                     ((self.ptr_reference + 1) * self.ptr_size)]
        try:
            ptr = self._unpack(value)
        except struct.error:
            return None
        # The value *must* be present (bit 0) since it's a mapped page
        # It's almost always writable (bit 1)
        # It's occasionally Super, but not reliably so, haven't checked when/why not
        # The top 3-bits are usually ignore (which in practice means 0
        # Need to find out why the middle 3-bits are usually 6 (0110)
        if ptr != 0 and (ptr & self.mask == data_offset + page_offset) & (ptr & 0xFF1 == 0x61):
            dtb = (ptr & self.mask)
            return self.second_pass(dtb, data, data_offset)
        return None

    def second_pass(self, dtb: int, data: bytes, data_offset: int) -> Optional[Tuple[int, Any]]:
        """Re-reads over the whole page to validate other records based on the
        number of pages marked user vs super.

        Args:
            dtb: The identified dtb that needs validating
            data: The chunk of data that contains the dtb to be validated
            data_offset: Where, within the layer, the chunk of data lives

        Returns:
            A valid DTB within this page
        """
        page = data[dtb - data_offset:dtb - data_offset + self.page_size]
        usr_count, sup_count = 0, 0
        for i in range(0, self.page_size, self.ptr_size):
            val = self._unpack(page[i:i + self.ptr_size])
            if val & 0x1:
                sup_count += 0 if (val & 0x4) else 1
                usr_count += 1 if (val & 0x4) else 0
        # print(hex(dtb), usr_count, sup_count, usr_count + sup_count)
        # We sometimes find bogus DTBs at 0x16000 with a very low sup_count and 0 usr_count
        # I have a winxpsp2-x64 image with identical usr/sup counts at 0x16000 and 0x24c00 as well as the actual 0x3c3000
        if usr_count or sup_count > 5:
            return dtb, None
        return None


class DtbTest32bit(DtbTest):

    def __init__(self) -> None:
        super().__init__(layer_type = layers.intel.WindowsIntel,
                         ptr_struct = "I",
                         ptr_reference = 0x300,
                         mask = 0xFFFFF000)


class DtbTest64bit(DtbTest):

    def __init__(self) -> None:
        super().__init__(layer_type = layers.intel.WindowsIntel32e,
                         ptr_struct = "Q",
                         ptr_reference = 0x1ED,
                         mask = 0x3FFFFFFFFFF000)


class DtbTestPae(DtbTest):

    def __init__(self) -> None:
        super().__init__(layer_type = layers.intel.WindowsIntelPAE,
                         ptr_struct = "Q",
                         ptr_reference = 0x3,
                         mask = 0x3FFFFFFFFFF000)

    def second_pass(self, dtb: int, data: bytes, data_offset: int) -> Optional[Tuple[int, Any]]:
        """PAE top level directory tables contains four entries and the self-
        referential pointer occurs in the second level of tables (so as not to
        use up a full quarter of the space).  This is very high in the space,
        and occurs in the fourht (last quarter) second-level table.  The
        second-level tables appear always to come sequentially directly after
        the real dtb.  The value for the real DTB is therefore four page
        earlier (and the fourth entry should point back to the `dtb` parameter
        this function was originally passed.

        Args:
            dtb: The identified self-referential pointer that needs validating
            data: The chunk of data that contains the dtb to be validated
            data_offset: Where, within the layer, the chunk of data lives

        Returns:
            Returns the actual DTB of the PAE space
        """
        dtb -= 0x4000
        # If we're not in something that the overlap would pick up
        if dtb - data_offset >= 0:
            pointers = data[dtb - data_offset + (3 * self.ptr_size):dtb - data_offset + (4 * self.ptr_size)]
            val = self._unpack(pointers)
            if (val & self.mask == dtb + 0x4000) and (val & 0xFFF == 0x001):
                return dtb, None
        return None


class DtbSelfReferential(DtbTest):
    """A generic DTB test which looks for a self-referential pointer at *any*
    index within the page."""

    def __init__(self, layer_type: Type[layers.intel.Intel], ptr_struct: str, ptr_reference: int, mask: int) -> None:
        super().__init__(layer_type = layer_type, ptr_struct = ptr_struct, ptr_reference = ptr_reference, mask = mask)

    def __call__(self, data: bytes, data_offset: int, page_offset: int) -> Optional[Tuple[int, int]]:
        page = data[page_offset:page_offset + self.page_size]
        if not page:
            return None
        ref_pages = set()
        for ref in range(0, self.page_size, self.ptr_size):
            ptr_data = page[ref:ref + self.ptr_size]
            if len(ptr_data) == self.ptr_size:
                ptr, = struct.unpack(self.ptr_struct, ptr_data)
                if ((ptr & self.mask) == (data_offset + page_offset)) and (data_offset + page_offset > 0):
                    ref_pages.add(ref)
        # The DTB is extremely unlikely to refer back to itself. so the number of reference should always be exactly 1
        if len(ref_pages) == 1:
            return (data_offset + page_offset), ref_pages.pop()
        return None


class DtbSelfRef32bit(DtbSelfReferential):

    def __init__(self):
        super().__init__(layer_type = layers.intel.WindowsIntel,
                         ptr_struct = "I",
                         ptr_reference = 0x300,
                         mask = 0xFFFFF000)


class DtbSelfRef64bit(DtbSelfReferential):

    def __init__(self) -> None:
        super().__init__(layer_type = layers.intel.WindowsIntel32e,
                         ptr_struct = "Q",
                         ptr_reference = 0x1ED,
                         mask = 0x3FFFFFFFFFF000)


class PageMapScanner(interfaces.layers.ScannerInterface):
    """Scans through all pages using DTB tests to determine a dtb offset and
    architecture."""
    overlap = 0x4000
    thread_safe = True
    tests = [DtbTest64bit(), DtbTest32bit(), DtbTestPae()]
    """The default tests to run when searching for DTBs"""

    def __init__(self, tests: List[DtbTest]) -> None:
        super().__init__()
        self.tests = tests

    def __call__(self, data: bytes, data_offset: int) -> Generator[Tuple[DtbTest, int], None, None]:
        for test in self.tests:
            for page_offset in range(0, len(data), 0x1000):
                result = test(data, data_offset, page_offset)
                if result is not None:
                    yield (test, result[0])


class WintelHelper(interfaces.automagic.AutomagicInterface):
    """Windows DTB finder based on self-referential pointers.

    This class adheres to the :class:`~volatility3.framework.interfaces.automagic.AutomagicInterface` interface
    and both determines the directory table base of an intel layer if one hasn't been specified, and constructs
    the intel layer if necessary (for example when reconstructing a pre-existing configuration).

    It will scan for existing TranslationLayers that do not have a DTB  using the :class:`PageMapScanner`
    """
    priority = 20
    tests = [DtbTest64bit(), DtbTest32bit(), DtbTestPae()]

    def __call__(self,
                 context: interfaces.context.ContextInterface,
                 config_path: str,
                 requirement: interfaces.configuration.RequirementInterface,
                 progress_callback: constants.ProgressCallback = None) -> None:
        useful = []
        sub_config_path = interfaces.configuration.path_join(config_path, requirement.name)
        if (isinstance(requirement, requirements.TranslationLayerRequirement)
                and requirement.requirements.get("class", False) and requirement.unsatisfied(context, config_path)):
            class_req = requirement.requirements["class"]

            for test in self.tests:
                if (test.layer_type.__module__ + "." + test.layer_type.__name__ == class_req.config_value(
                        context, sub_config_path)):
                    useful.append(test)

            # Determine if a class has been chosen
            # Once an appropriate class has been chosen, attempt to determine the page_map_offset value
            if ("memory_layer" in requirement.requirements
                    and not requirement.requirements["memory_layer"].unsatisfied(context, sub_config_path)):
                # Only bother getting the DTB if we don't already have one
                page_map_offset_path = interfaces.configuration.path_join(sub_config_path, "page_map_offset")
                if not context.config.get(page_map_offset_path, None):
                    physical_layer_name = requirement.requirements["memory_layer"].config_value(
                        context, sub_config_path)
                    if not isinstance(physical_layer_name, str):
                        raise TypeError("Physical layer name is not a string: {}".format(sub_config_path))
                    physical_layer = context.layers[physical_layer_name]
                    # Check lower layer metadata first
                    if physical_layer.metadata.get('page_map_offset', None):
                        context.config[page_map_offset_path] = physical_layer.metadata['page_map_offset']
                    else:
                        hits = physical_layer.scan(context, PageMapScanner(useful), progress_callback)
                        for test, dtb in hits:
                            context.config[page_map_offset_path] = dtb
                            break
                        else:
                            return None
                if isinstance(requirement, interfaces.configuration.ConstructableRequirementInterface):
                    requirement.construct(context, config_path)
        else:
            for subreq in requirement.requirements.values():
                self(context, sub_config_path, subreq)


class WindowsIntelStacker(interfaces.automagic.StackerLayerInterface):
    stack_order = 40
    exclusion_list = ['mac', 'linux']

    @classmethod
    def stack(cls,
              context: interfaces.context.ContextInterface,
              layer_name: str,
              progress_callback: constants.ProgressCallback = None) -> Optional[interfaces.layers.DataLayerInterface]:
        """Attempts to determine and stack an intel layer on a physical layer
        where possible.

        Where the DTB scan fails, it attempts a heuristic of checking
        for the DTB within a specific range. New versions of windows,
        with randomized self-referential pointers, appear to always load
        their dtb within a small specific range (`0x1a0000` and
        `0x1b0000`), so instead we scan for all self-referential
        pointers in that range, and ignore any that contain multiple
        self-references (since the DTB is very unlikely to point to
        itself more than once).
        """
        base_layer = context.layers[layer_name]
        if isinstance(base_layer, intel.Intel):
            return None
        if base_layer.metadata.get('os', None) not in ['Windows', 'Unknown']:
            return None
        layer = config_path = None

        # Check the metadata
        if (base_layer.metadata.get('os', None) == 'Windows' and base_layer.metadata.get('page_map_offset')):
            arch = base_layer.metadata.get('architecture', None)
            if arch not in ['Intel32', 'Intel64']:
                return None
            # Set the layer type
            layer_type = intel.WindowsIntel  # type: Type
            if arch == 'Intel64':
                layer_type = intel.WindowsIntel32e
            elif base_layer.metadata.get('pae', False):
                layer_type = intel.WindowsIntelPAE
            # Construct the layer
            new_layer_name = context.layers.free_layer_name("IntelLayer")
            config_path = interfaces.configuration.path_join("IntelHelper", new_layer_name)
            context.config[interfaces.configuration.path_join(config_path, "memory_layer")] = layer_name
            context.config[interfaces.configuration.path_join(
                config_path, "page_map_offset")] = base_layer.metadata['page_map_offset']
            layer = layer_type(context, config_path = config_path, name = new_layer_name, metadata = {'os': 'Windows'})

        # Check for the self-referential pointer
        if layer is None:
            hits = base_layer.scan(context, PageMapScanner(WintelHelper.tests))
            layer = None
            config_path = None
            for test, dtb in hits:
                new_layer_name = context.layers.free_layer_name("IntelLayer")
                config_path = interfaces.configuration.path_join("IntelHelper", new_layer_name)
                context.config[interfaces.configuration.path_join(config_path, "memory_layer")] = layer_name
                context.config[interfaces.configuration.path_join(config_path, "page_map_offset")] = dtb
                layer = test.layer_type(context,
                                        config_path = config_path,
                                        name = new_layer_name,
                                        metadata = {'os': 'Windows'})
                break

        # Fall back to a heuristic for finding the Windows DTB
        if layer is None:
            vollog.debug("Self-referential pointer not in well-known location, moving to recent windows heuristic")
            # There is a very high chance that the DTB will live in this narrow segment, assuming we couldn't find it previously
            hits = context.layers[layer_name].scan(context,
                                                   PageMapScanner([DtbSelfRef64bit()]),
                                                   sections = [(0x1a0000, 0x50000)],
                                                   progress_callback = progress_callback)
            # Flatten the generator
            hits = list(hits)
            if hits:
                # TODO: Decide which to use if there are multiple options
                test, page_map_offset = hits[0]
                new_layer_name = context.layers.free_layer_name("IntelLayer")
                config_path = interfaces.configuration.path_join("IntelHelper", new_layer_name)
                context.config[interfaces.configuration.path_join(config_path, "memory_layer")] = layer_name
                context.config[interfaces.configuration.path_join(config_path, "page_map_offset")] = page_map_offset
                # TODO: Need to determine the layer type (chances are high it's x64, hence this default)
                layer = layers.intel.WindowsIntel32e(context,
                                                     config_path = config_path,
                                                     name = new_layer_name,
                                                     metadata = {'os': 'Windows'})
        if layer is not None and config_path:
            vollog.debug("DTB was found at: 0x{:0x}".format(context.config[interfaces.configuration.path_join(
                config_path, "page_map_offset")]))
        return layer


class WinSwapLayers(interfaces.automagic.AutomagicInterface):
    """Class to read swap_layers filenames from single-swap-layers, create the
    layers and populate the single-layers swap_layers."""

    def __call__(self,
                 context: interfaces.context.ContextInterface,
                 config_path: str,
                 requirement: interfaces.configuration.RequirementInterface,
                 progress_callback: constants.ProgressCallback = None) -> None:
        """Finds translation layers that can have swap layers added."""
        path_join = interfaces.configuration.path_join
        self._translation_requirement = self.find_requirements(context,
                                                               config_path,
                                                               requirement,
                                                               requirements.TranslationLayerRequirement,
                                                               shortcut = False)
        for trans_sub_config, trans_req in self._translation_requirement:
            if not isinstance(trans_req, requirements.TranslationLayerRequirement):
                # We need this so the type-checker knows we're a TranslationLayerRequirement
                continue
            swap_sub_config, swap_req = self.find_swap_requirement(trans_sub_config, trans_req)
            counter = 0
            swap_config = interfaces.configuration.parent_path(swap_sub_config)

            if swap_req and swap_req.unsatisfied(context, swap_config):
                # See if any of them need constructing
                for swap_location in self.config.get('single_swap_locations', []):
                    # Setup config locations/paths
                    current_layer_name = swap_req.name + str(counter)
                    current_layer_path = path_join(swap_sub_config, current_layer_name)
                    layer_loc_path = path_join(current_layer_path, "location")
                    layer_class_path = path_join(current_layer_path, "class")
                    counter += 1

                    # Fill in the config
                    if swap_location:
                        context.config[current_layer_path] = current_layer_name
                        context.config[layer_loc_path] = swap_location
                        context.config[layer_class_path] = 'volatility3.framework.layers.physical.FileLayer'

                    # Add the requirement
                    new_req = requirements.TranslationLayerRequirement(name = current_layer_name,
                                                                       description = "Swap Layer",
                                                                       optional = False)
                    swap_req.add_requirement(new_req)

                context.config[path_join(swap_sub_config, 'number_of_elements')] = counter
                context.config[swap_sub_config] = True

                swap_req.construct(context, swap_config)

    @staticmethod
    def find_swap_requirement(config: str,
                              requirement: requirements.TranslationLayerRequirement) \
            -> Tuple[str, Optional[requirements.LayerListRequirement]]:
        """Takes a Translation layer and returns its swap_layer requirement."""
        swap_req = None
        for req_name in requirement.requirements:
            req = requirement.requirements[req_name]
            if isinstance(req, requirements.LayerListRequirement) and req.name == 'swap_layers':
                swap_req = req
                continue

        swap_config = interfaces.configuration.path_join(config, 'swap_layers')
        return swap_config, swap_req

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        """Returns the requirements of this plugin."""
        return [
            requirements.ListRequirement(
                name = "single_swap_locations",
                element_type = str,
                min_elements = 0,
                max_elements = 16,
                description = "Specifies a list of swap layer URIs for use with single-location",
                optional = True)
        ]
