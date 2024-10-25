# This file is Copyright 2024 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

import enum
import logging
import struct
import os
import json
import math
import struct
import hashlib
from typing import Type, Optional, List


from volatility3.framework import interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.interfaces import plugins
from volatility3.framework.renderers import format_hints
from volatility3.framework.layers import intel

vollog = logging.getLogger(__name__)


class PageGlobalDirectoryScanner(interfaces.layers.ScannerInterface):

    def __init__(
        self,
        memory_size: int,
        intel_class=intel.Intel32e,
    ):
        """Init the PageGlobalDirectoryScanner.

        Args:
            memory_size: The total size in bytes of the physical memory layer to be scanned
            intel_class: The layer class (e.g. intel.Intel32e) used to detmine page size, table structure etc
        """
        super().__init__()

        if intel_class != intel.Intel32e:
            raise NotImplementedError(
                "Only intel.Intel32e is currently supported in PageGlobalDirectoryScanner"
            )
        self._intel_class = intel_class
        self._memory_size = memory_size

        # This is needed to correctly mask the lower bits of an entry, normally only
        # calculated in the __init__ for an intel layer but we have not yet constructed
        # an intel layer.
        self._index_shift = int(
            math.ceil(math.log2(struct.calcsize(self._intel_class._entry_format)))
        )

        # calculate the total number of entries that will existper page given the
        # size of the entry.
        self._number_of_pointers_per_page = (
            self._intel_class.page_size
            // struct.calcsize(self._intel_class._entry_format)
        )

        # TODO: reformat this, requires that all layers use a pack format like '<I' or '<Q'
        # and this feels too much of a hack to just slice into 0 and 1.
        # this is the string used page struct to pack the full page of pointers into ints
        self._pack_string = (
            self._intel_class._entry_format[0]
            + self._intel_class._entry_format[1] * self._number_of_pointers_per_page
        )

    def _validate_page_table(self, page_data: bytes, position: int = 0):
        """
        Returns:
            An open FileInterface object containing the complete data for the mapping or None in the case of failure
        """
        page_size = self._intel_class.page_size

        # check that page_data is the correct size
        if len(page_data) != page_size:
            return None

        # hash the high half of the page table
        khash = hashlib.sha1(page_data[page_size // 2 :]).hexdigest()

        page_pointers = struct.unpack(self._pack_string, page_data)

        # test for empty page
        if all(pointer == 0 for pointer in page_pointers):
            return None

        # test for empty high page
        if all(
            pointer == 0
            for pointer in page_pointers[self._number_of_pointers_per_page // 2 :]
        ):
            return None

        # read size from layer strcutre
        _name, size, _large_page = self._intel_class._structure[position]

        # mask pointers to remove high and low bits not used as part of the address to the next
        # table.  This removes  XD or 'Execute Disable' bit etc
        page_pointers = [
            self._intel_class._mask(
                pointer, self._intel_class._maxvirtaddr, size + self._index_shift
            )
            for pointer in page_pointers
        ]
        # test that all pointers fit within memory
        if any(self._memory_size < pointer for pointer in page_pointers):
            return None

        # test all non zero pointers are unique
        non_zero_pointers = [pointer for pointer in page_pointers if pointer > 0]
        if len(non_zero_pointers) != len(set(non_zero_pointers)):
            return None

        # all tests passed
        return khash

    def __call__(self, data: bytes, data_offset: int):
        """Scans every page, to see whether this may be a valid PGD

        Args:
            data: the actual data to be scanned
            data_offset: the offset to where this data begins in relation to the layer being scanned

        Yields:
            offset: The offset of the match
            page_data: The full page data of the match
            khash: A SHA1 of the high half of the match
        """

        page_size = self._intel_class.page_size

        for page_start in range(
            data_offset % page_size,
            len(data),
            page_size,
        ):
            page_data = data[page_start : page_start + page_size]

            # validate page as being a likely pgd
            khash = self._validate_page_table(page_data)

            # if a likely valid PGD was located, and therefore a khash calculated, yield the results
            if khash:
                if page_start + data_offset < self._memory_size:
                    yield (
                        page_start + data_offset,
                        data[page_start : page_start + self._intel_class.page_size],
                        khash,
                    )


class PGDScan(plugins.PluginInterface):
    """Heuristically scans for Page Global Directories and generates volatility configs for them,
    it can also dump the memeory for the PGDs that have been located. Not designed to correctly
    recover PGD for virtual machines - please use the vmscan plugin.

    Currently only supports 64-bit Intel32e architectures.

    This plugin can allow analysis of virtual memeory when an ISF is unaviabale."""

    _required_framework_version = (2, 2, 0)
    MAXSIZE_DEFAULT = 1024 * 1024 * 1024  # 1 Gb

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        # TODO: perhaps allow user to provide a needle, e.g. "/bin/bash" and only return
        # the layers where that needle hits?
        return [
            requirements.TranslationLayerRequirement(
                name="primary", description="Physical base memory layer"
            ),
            requirements.ListRequirement(
                name="offset",
                description="Only scan these selected pages. Useful for dumping out only a sinlge PGD",
                element_type=int,
                optional=True,
            ),
            requirements.BooleanRequirement(
                name="save-configs",
                description="Save configuration JSON file to a file for each recovered PGD",
                optional=True,
                default=False,
            ),
            requirements.BooleanRequirement(
                name="dump",
                description="Extract private memory regions for recovered PGDs",
                optional=True,
                default=False,
            ),
            requirements.IntRequirement(
                name="maxsize",
                description="Maximum size for dumped memory regions "
                "(all the bigger sections will be ignored)",
                default=cls.MAXSIZE_DEFAULT,
                optional=True,
            ),
        ]

    def _dump(
        self,
        context: interfaces.context.ContextInterface,
        layer_name: str,
        start: int,
        size: int,
        open_method: Type[interfaces.plugins.FileHandlerInterface],
        maxsize: int = MAXSIZE_DEFAULT,
    ) -> Optional[interfaces.plugins.FileHandlerInterface]:
        """Extracts the complete data for a mapping as a FileInterface.

        Args:
            context: The context to retrieve required elements from
            layer_name: the name of the layer to dump from
            start: The start virtual address from the layer to dump
            size: The size of data within the layer to dump
            open_method: class to provide context manager for opening the file
            maxsize: Max size of section (default MAXSIZE_DEFAULT)

        Returns:
            An open FileInterface object containing the complete data for the mapping or None in the case of failure
        """

        layer = context.layers[layer_name]

        # check if vm_size is larger than the maxsize limit, and therefore is not saved out.
        if maxsize <= size:
            vollog.warning(
                f"Skip virtual memory dump for {start:#x} as {size} is larger than maxsize limit of {maxsize}"
            )
            return None

        file_name = f"pgd.{layer._page_map_offset:#x}.start.{start:#x}.dmp"
        try:
            file_handle = open_method(file_name)
            chunk_size = 1024 * 1024 * 10
            offset = start
            while offset < start + size:
                to_read = min(chunk_size, start + size - offset)
                data = layer.read(offset, to_read, pad=True)
                file_handle.write(data)
                offset += to_read
        except Exception as excp:
            vollog.debug(f"Unable to dump virtual memory {file_name}: {excp}")
            return None
        return file_handle

    def _generator(self):
        # get primary layer
        layer = self.context.layers[self.config["primary"]]

        # Try to move down to the highest physical layer
        if layer.config.get("memory_layer"):
            layer = self.context.layers[layer.config["memory_layer"]]

        # TODO: test and support other intel layers, either automatically
        # detecting the likely type or allowing the user to provide it as
        # a requirement option.
        intel_class = intel.Intel32e

        # get max layer address, this is used to validate possible PGDs as they
        # cannot have pointers beyond the end of physical memory
        maximum_address = layer.maximum_address

        offsets = self.config.get("offset")
        if offsets:
            sections = [(offset, intel_class.page_size) for offset in offsets]
        else:
            sections = None

        # store results of the scanning in a lookup so that the most frequent result
        # can then be shown to the user.
        khash_lookup = {}

        # Run the scan
        for pgd_offset, _pgd_data, khash in layer.scan(
            self.context,
            PageGlobalDirectoryScanner(maximum_address, intel_class=intel_class),
            self._progress_callback,
            sections=sections,
        ):
            if khash not in khash_lookup:
                khash_lookup[khash] = []
            khash_lookup[khash].append(pgd_offset)

        # join is used a lot when building temp layers, this is simply
        # here to make the code a little easier to read
        join = interfaces.configuration.path_join

        # find the most common khash, given that all user processes
        # share the same kernel it is the most common khash that will
        # locate the likely pgds

        max_pgd_count = 0
        most_common_khash = ""
        for khash, pgds in khash_lookup.items():
            if len(pgds) > max_pgd_count:
                max_pgd_count = len(pgds)
                most_common_khash = khash

        for pgd_offset in khash_lookup[most_common_khash]:

            # build a new layer for this likely pgd
            temp_context = self.context.clone()
            temp_layer_name = self.context.layers.free_layer_name("IntelLayer")
            # temp_layer_name = "primary" # I would like to use the name primary but not sure how?
            config_path = join("IntelHelper", temp_layer_name)
            temp_context.config[join(config_path, "memory_layer")] = "memory_layer"
            temp_context.config[join(config_path, "page_map_offset")] = pgd_offset
            temp_layer = intel_class(
                temp_context,
                config_path=config_path,
                name=temp_layer_name,
            )
            temp_context.add_layer(temp_layer)

            config_fname = "-"
            if self.config.get("save-configs"):
                # TODO: Fix this. It seems like an ungly hack and must to the wrong way
                # to make a new config with a new primary layer?
                conf = {}
                for key, value in dict(temp_layer.build_configuration()).items():
                    conf[f"primary.{key}"] = value
                # finished hacking config

                # save config to disk
                config_fname = f"pgd.{pgd_offset:#x}.json"
                with open(config_fname, "w") as f:
                    json.dump(
                        conf,
                        f,
                        sort_keys=True,
                        indent=2,
                    )
                    f.write("\n")

            # calculate the total size of the user mem
            user_max_addr = 1 << (temp_layer._maxvirtaddr - 1)

            # get mapping for this temp layer
            temp_layer_mapping = [
                (offset, sublength)
                for (
                    offset,
                    sublength,
                    _mapped_offset,
                    _mapped_length,
                    _layer,
                ) in temp_layer.mapping(0, user_max_addr, ignore_errors=True)
            ]

            # calculate the total size in bytes for the user part of the layer
            total_user_size = sum(
                [sublength for _offset, sublength in temp_layer_mapping]
            )

            # display result to user
            yield (0, (format_hints.Hex(pgd_offset), total_user_size, config_fname))

            # dump put memory if requested
            # TODO: perhaps merge regions that are quite close together, if might be more useful to
            # have fewer files with a few extra blank pages than to have the highly accurate result
            # of 100s of tiny regions saved to there own files.
            if self.config.get("dump"):
                for offset, sublength in temp_layer_mapping:
                    self._dump(
                        temp_context, temp_layer.name, offset, sublength, self.open
                    )

    def run(self):
        # TODO: Implement scanning for 32bit PGDs!

        return renderers.TreeGrid(
            [("PGD offset", format_hints.Hex), ("size", int), ("config", str)],
            self._generator(),
        )
