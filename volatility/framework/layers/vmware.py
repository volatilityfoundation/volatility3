import os
import struct
from urllib import parse

from volatility.framework import interfaces
from volatility.framework.configuration import requirements
from volatility.framework.layers import physical, segmented


class VmwareLayer(segmented.SegmentedLayer):
    provides = {"type": "physical"}
    priority = 22

    header_structure = "<4sII"
    group_structure = "64sQQ"

    def __init__(self, context, config_path, name):
        # Construct these so we can use self.config
        self._context = context
        self._config_path = config_path
        self._base_layer, self._meta_layer = self.config["base_layer"], self.config["meta_layer"]
        # Then call the super, which will call load_segments (which needs the base_layer before it'll work)
        super().__init__(context, config_path = config_path, name = name)

    def _load_segments(self):
        """Loads up the segments from the meta_layer"""
        self._read_header()

    def _read_header(self):
        """Checks the vmware header to make sure it's valid"""
        meta_layer = self.context.memory.get(self._meta_layer, None)
        header_size = struct.calcsize(self.header_structure)
        data = meta_layer.read(0, header_size)
        magic, unknown, groupCount = struct.unpack(self.header_structure, data)
        if magic not in [b"\xD2\xBE\xD2\xBE"]:
            raise ValueError("Wrong magic bytes for Vmware layer: {}".format(repr(magic)))

        version = magic[1] & 0xf

        group_size = struct.calcsize(self.group_structure)

        groups = {}
        for group in range(groupCount):
            name, tag_location, _unknown = struct.unpack(self.group_structure,
                                                         meta_layer.read(header_size + (group * group_size),
                                                                         group_size))
            name = name.rstrip(b"\x00")
            groups[name] = tag_location
        memory = groups[b"memory"]

        tags_read = False
        offset = memory
        tags = {}
        while not tags_read:
            flags = ord(meta_layer.read(offset, 1))
            name_len = ord(meta_layer.read(offset + 1, 1))
            tags_read = (flags == 0) and (name_len == 0)
            if not tags_read:
                name = self._context.object("string", layer_name = self._meta_layer, offset = offset + 2,
                                            max_length = name_len)
                indicies_len = (flags >> 6) & 3
                indicies = self._context.object("array",
                                                count = indicies_len,
                                                subtype = self.context.symbol_space.get_type("unsigned int"),
                                                offset = 2 + name_len,
                                                layer_name = self._meta_layer)
                offset += 2 + name_len + (indicies_len * struct.calcsize("I"))
                data = self._context.object("unsigned int", layer_name = self._meta_layer, offset = offset)
                offset += self._context.symbol_space.get_type("unsigned int").size

                tags[name] = (flags, indicies, data)

        for region in range(tags["regionsCount"][2]):
            offset = tags["regionPPN"][1][region]
            mapped_offset = tags["regionPageNum"][1][region]
            length = tags["regionSize"][1][region]
            self._segments.append((offset, mapped_offset, length))

    @property
    def dependencies(self):
        return [self._base_layer, self._meta_layer]

    @classmethod
    def get_requirements(cls):
        """This vmware translation layer always requires a separate metadata layer"""
        return [requirements.TranslationLayerRequirement(name = 'base_layer',
                                                         optional = False),
                requirements.TranslationLayerRequirement(name = 'meta_layer',
                                                         optional = False)
                ]


class VmwareStacker(interfaces.automagic.StackerLayerInterface):
    @classmethod
    def stack(cls, context, layer_name):
        """Attempt to stack this based on the starting information"""
        if not isinstance(context.memory[layer_name], physical.FileLayer):
            return
        if not context.config.get("automagic.general.single_location", None):
            return
        location = parse.urlparse(context.config["automagic.general.single_location"])
        if location.path.endswith(".vmem"):
            vmss = location.path[:-5] + ".vmss"
            vmsn = location.path[:-5] + ".vmsn"
            current_layer_name = context.memory.free_layer_name("VmwareMetaLayer")
            current_config_path = interfaces.configuration.path_join("automagic", "layer_stacker", "stack",
                                                                     current_layer_name)
            if os.path.exists(vmss):
                context.config[interfaces.configuration.path_join(current_config_path, "filename")] = vmss
                context.memory.add_layer(physical.FileLayer(context, current_config_path, current_layer_name))
            elif os.path.exists(vmsn):
                context.config[interfaces.configuration.path_join(current_config_path, "filename")] = vmss
                context.memory.add_layer(physical.FileLayer(context, current_config_path, current_layer_name))
            else:
                return
            new_layer_name = context.memory.free_layer_name("VmwareLayer")
            context.config[interfaces.configuration.path_join(current_config_path, "base_layer")] = layer_name
            context.config[
                interfaces.configuration.path_join(current_config_path, "meta_layer")] = current_layer_name
            new_layer = VmwareLayer(context, current_config_path, new_layer_name)
            return new_layer
