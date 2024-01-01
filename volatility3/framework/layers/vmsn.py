# This file is Copyright 2024 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

from typing import Any, Dict, Optional, Tuple
from volatility3.framework import constants, exceptions, interfaces, objects
from volatility3.framework.layers import segmented
from volatility3.framework.symbols import intermed


class VMSNException(exceptions.LayerException):
    pass


class _VMWARE_GROUP(objects.StructType):
    """Class to represent the Group objects"""

    def get_name(self) -> str:
        return self.name.cast("string", max_length=64)


class _VMWARE_TAG(objects.StructType):
    """Class to house the tag and meta-tag structures"""

    @property
    def extended(self) -> bool:
        """Determines whether the additional size values are int or long long"""
        return (self.flags & 0x3E) == 0x3E

    def _symbol(self, name: str) -> str:
        """Make a symbol from this symbol's table"""
        (table, _) = self.vol.type_name.split(constants.BANG)
        return table + constants.BANG + name

    @property
    def indices(self):
        """Returns the indicies for this tag"""
        num_indices = (self.flags >> 6) & 0x3
        indices = self._context.object(
            self._symbol("array"),
            self.vol.layer_name,
            offset=self.vol.offset + self.name_length + 2,
            count=num_indices,
            subtype=self._context.symbol_space.get_type(self._symbol("unsigned long")),
        )
        return indices

    def get_data_details(self, version: int = 0) -> Tuple[int, int]:
        """Returns the offset and disk size of the tag data"""
        size = self.flags & 0x3F

        tag_es_structure = (
            "tag_extended_size" if version == 0 else "tag_extended_size64"
        )
        offset = self.indices.vol.offset + self.indices.vol.size

        if self.extended:
            extended_sizes = self._context.object(
                self._symbol(tag_es_structure),
                self.vol.layer_name,
                offset=offset,
            )
            offset = (
                extended_sizes.padding_len + extended_sizes.padding_len.vol.offset + 2
            )
            size = extended_sizes.data_size

        return offset, size

    def get_data(self, version: int = 0) -> bytes:
        """Returns the tag data"""

        offset, size = self.get_data_details(version)

        return self._context.layers[self.vol.layer_name].read(offset, size)

    def get_name(self) -> str:
        """Returns the name of the tag"""
        return self.name.cast("string", max_length=self.name_length)


class VMSNLayer(segmented.SegmentedLayer):
    """Layer for loading and reading data from the VMware SNapshot file format (VMSN).
    Based on work by Nir Izraeli's  and Michael Hale Leigh.

    Format:

    +-------------------------------------+
    | Header                              |
    +-------------------------------------+
    | Groups                              |
    +-------------------------------------+
    ~                                     ~
    | Tags                                |
    ~                                     ~
    +-------------------------------------+

    Group:
    +-------------------------------------+
    | name[64]                            |
    | tags -> Tags                        |
    +-------------------------------------+

    Tag:
    +-------------------------------------+
    | Flags[1]                            |
    | NameLen[1]                          |
    | Name[NameLen]                       |
    | Indicies[(Flags & 0x3F) >> 6]       |
    | if Flags & 0x3E = 0x3E:             |
    |   DataDiskSize[4 or 8]              |
    |   DataMemSize[4 or 8]               |
    |   PaddingLen[2]                     |
    |   Padding[PaddingLen]               |
    +-------------------------------------+
    """

    valid_signatures = [
        b"\xd2\xbe\xd0\xbe",
        b"\xd2\xbe\xd2\xbe",
        b"\xd3\xbe\xd3\xbe",
        b"\xd1\xba\xd1\xba",
    ]

    def __init__(
        self, context: interfaces.context.ContextInterface, config_path: str, name: str
    ) -> None:
        self._vmsn_table_name = None
        super().__init__(context, config_path, name)
        # The base class loads the segments on initialization, but otherwise this must to get the right min/max addresses

    def symbol(self, name: str) -> str:
        """Returns the full symbol name for a symbol from the VMSN symbol table"""
        if self._vmsn_table_name:
            return self._vmsn_table_name + constants.BANG + name
        return name

    @classmethod
    def _check_header(
        cls, base_layer: interfaces.layers.DataLayerInterface, offset: int = 0
    ) -> Tuple[int, int]:
        signature = base_layer.read(0, 4)
        return signature in cls.valid_signatures

    def _load_segments(self):
        """"""
        if not self._check_header(self.context.layers[self._base_layer]):
            raise VMSNException(self._base_layer_name, "No VMSN header found")

        if not self._vmsn_table_name:
            self._vmsn_table_name = intermed.IntermediateSymbolTable.create(
                self.context, self.config_path, "generic", "vmsn"
            )
            vmsn_table = self.context.symbol_space[self._vmsn_table_name]
            vmsn_table.set_type_class("group", _VMWARE_GROUP)
            vmsn_table.set_type_class("tag", _VMWARE_TAG)

        self._read_tags()

    def _read_tags(self) -> Dict[str, Dict[str, Any]]:
        """Reads the tags from the header and constructs a suitable tree"""
        header = self.context.object(self.symbol("header"), self._base_layer, 0)

        header.groups.count = header.group_count

        for group in header.groups:
            if group.get_name() == "memory":
                tag_offset = group.tags
                tag = self.context.object(
                    self.symbol("tag"), self._base_layer, tag_offset
                )
                while tag.name_length != 0 and tag.flags != 0:
                    print(f"{tag.get_name()} {[x for x in tag.indices]}")
                    data_offset, data_size = tag.get_data_details(header.magic & 0xF)
                    next_offset = data_offset + data_size
                    if (
                        group.get_name() == "memory"
                        and tag.get_name() == "regionsCount"
                    ):
                        pass
                    if group.get_name() == "memory" and tag.get_name() == "Memory":
                        print("Memory:", tag.indices)

                    # Next
                    tag = self.context.object(
                        self.symbol("tag"), self._base_layer, next_offset
                    )


class VMSNStacker(interfaces.automagic.StackerLayerInterface):
    stack_order = 10

    @classmethod
    def stack(
        cls,
        context: interfaces.context.ContextInterface,
        layer_name: str,
        progress_callback: constants.ProgressCallback = None,
    ) -> Optional[interfaces.layers.DataLayerInterface]:
        if not VMSNLayer._check_header(context.layers[layer_name]):
            return None
        new_name = context.layers.free_layer_name("VMSNLayer")
        context.config[
            interfaces.configuration.path_join(new_name, "base_layer")
        ] = layer_name
        return VMSNLayer(context, new_name, new_name)
