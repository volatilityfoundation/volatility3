import logging
import math
import struct

from volatility.framework import exceptions, interfaces
from volatility.framework.configuration import requirements
from volatility.framework.layers import intel

vollog = logging.getLogger(__name__)

validity_tests = {intel.Intel: [],
                  intel.IntelPAE: [],
                  intel.Intel32e: [(0b10111011, 0b00100011),
                                   (0b1, 0b1),
                                   (0b1111011, 0b1100011),
                                   (0b1111011, 0b1100011)]}


class NlpDtbScanner(interfaces.layers.ScannerInterface):
    """A scanner that checks for a mapping (and no invalid mappings) to quickly identify DTBs

    A secondary method to test the initial returns should be used to reduce false positives.

    Some of the masks used are heuristics, but have been tested against recent
    images from OSX, Windows, and Linux.
    """

    # Overlap must be a multiple of the page size
    overlap = 0x4000

    def __init__(self, layer_class, physical_layer):
        super().__init__()
        self._layer_class = layer_class
        self._physical_layer = physical_layer

    def test_entries(self, valid_entries):
        """Scans through valid_entries, descending to see whether one can be successfully mapped to completion

        Returns the first valid DTB or None is no valid DTBs could be found
        """
        for _, entry in valid_entries:
            if self.test_entry(entry, 1):
                return True
        return False

    def _get_mask(self, value):
        """Returns a value that correctly masks all numbers less than that of value"""
        bits = int(math.ceil(math.log(value, 2)))
        return (1 << (bits + 1)) - 1

    def test_entry(self, entry, level = 0):
        """Tests an individual entry at a particular level in the structure"""
        name, size, large_page = self._layer_class.structure[level]

        # Test the page for validity
        validity_mask, validity_success = validity_tests[self._layer_class][level]
        if not (entry & validity_mask == validity_success):
            return False

        # If it's a large page, we accept that it maps appropriately.
        if large_page and (entry & (1 << 7)):
            return True

        # Short circuit out if the entry is the last level and we're valid
        if level == len(self._layer_class.structure) - 1:
            return True

        # Somewhat hacky means of determining which format string to use
        format_str = 'Q'
        if size == 10:
            format_str = 'I'

        # We're going to check all entries, so we don't need to figure out indexes
        # or cut up any addresses
        page_bits = math.ceil(math.log2(self._layer_class.page_size))
        next_table_offset = (entry & self._get_mask(self._layer_class.maximum_address)) >> page_bits

        try:
            next_table = self._physical_layer.read(next_table_offset, self._layer_class.page_size)
        except exceptions.InvalidAddressException:
            return False

        calcsize = struct.calcsize('<' + str(2 ** size) + format_str)
        if calcsize > self._layer_class.page_size:
            raise ValueError("Size of number of entries cannot exceed a single page")
        new_entries = struct.unpack('<' + str(2 ** size) + format_str, next_table)
        for new_entry in new_entries:
            if self.test_entry(new_entry, level + 1):
                return True
        return False

    def __call__(self, data, data_offset):
        structure = self._layer_class.structure
        name, size, large_page = structure[0]

        # Somewhat hacky means of determining which format string to use
        format_str = 'Q'
        if size == 10:
            format_str = 'I'

        for page_offset in range(0, len(data), self._layer_class.page_size):
            calcsize = struct.calcsize('<' + str(2 ** size) + format_str)
            if calcsize > self._layer_class.page_size:
                raise ValueError("Size of number of entries cannot exceed a single page")
            if len(data[page_offset:page_offset + calcsize]) < calcsize:
                continue
            entries = struct.unpack('<' + str(2 ** size) + format_str, data[page_offset:page_offset + calcsize])
            valid_entries = []
            invalid_count = 0
            user_count = 0
            supervisor_count = 0

            entry_num = 0
            validity_mask, validity_success = validity_tests[self._layer_class][0]
            for entry in entries:
                if (entry & validity_mask) == validity_success:
                    valid_entries.append((entry_num, entry))

                    if (entry & (1 << 2)):
                        user_count = user_count + 1
                    else:
                        supervisor_count = supervisor_count + 1

                elif entry != 0:
                    invalid_count = invalid_count + 1

                entry_num = entry_num + 1

            if invalid_count == 0 and len(valid_entries) > 3 and user_count != 0 and supervisor_count != 0:
                yield (data_offset + page_offset, valid_entries)


class NlpDtbfinder(interfaces.automagic.AutomagicInterface):
    """Operating-system agnostic DirectoryTableBase scanner

    Checks a page for references off to other pages.
    """
    priority = 11

    def __call__(self, context, config_path, requirement, progress_callback = None):
        results = {}
        sub_config_path = interfaces.configuration.path_join(config_path, requirement.name)
        if (not interfaces.configuration.path_join(sub_config_path, "page_map_offset") in context.config and
                isinstance(requirement, requirements.TranslationLayerRequirement) and
                requirement.requirements.get("class", None)):
            class_req = requirement.requirements["class"]
            for layer_class in validity_tests:
                if (layer_class.__module__ + "." + layer_class.__name__ == class_req.config_value(context,
                                                                                                  sub_config_path)):

                    if ("memory_layer" in requirement.requirements and
                            not requirement.requirements["memory_layer"].unsatisfied(context, sub_config_path)):
                        physical_layer = requirement.requirements["memory_layer"].config_value(context, sub_config_path)

                        valid_entries = context.memory[physical_layer].scan(context,
                                                                            NlpDtbScanner(layer_class,
                                                                                          physical_layer),
                                                                            progress_callback)
                        results[layer_class] = physical_layer, valid_entries

            for layer_class in results:
                physical_layer, sub_results = results[layer_class]
                for dtb, valid_entries in sub_results:
                    if NlpDtbScanner(layer_class, self.context.memory[physical_layer]).test_entries(valid_entries):
                        context.config[
                            interfaces.configuration.path_join(sub_config_path, "page_map_offset")] = dtb
                        requirement.construct(context, config_path)
                        break
        else:
            for subreq in requirement.requirements.values():
                self(context, sub_config_path, subreq)


class NlpDtbStacker(interfaces.automagic.StackerLayerInterface):
    stack_order = 13

    @classmethod
    def stack(cls, context, layer_name, progress_callback = None):
        """Attempts to determine and stack an intel layer on a physical layer where possible"""
        if isinstance(context.memory[layer_name], intel.Intel):
            return None
        layer, dtb = None, 0
        for layer_class in validity_tests:
            scanner = NlpDtbScanner(layer_class, context.memory[layer_name])
            results = context.memory[layer_name].scan(context, scanner, progress_callback)
            for dtb, valid_entries in results:
                if scanner.test_entries(valid_entries):
                    new_layer_name = context.memory.free_layer_name("IntelLayer")
                    config_path = interfaces.configuration.path_join("IntelHelper", new_layer_name)
                    context.config[interfaces.configuration.path_join(config_path, "memory_layer")] = layer_name
                    context.config[interfaces.configuration.path_join(config_path, "page_map_offset")] = dtb
                    layer = layer_class(context, config_path = config_path, name = new_layer_name)
                    break
            if layer is not None:
                break
        if layer is not None:
            vollog.debug("DTB was found at: 0x{:0x}".format(dtb))
        return layer
