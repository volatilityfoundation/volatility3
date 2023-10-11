# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
import contextlib
import logging
import struct
from typing import Any, Dict, List, Optional

from volatility3.framework import constants, exceptions, interfaces
from volatility3.framework.configuration import requirements
from volatility3.framework.layers import physical, resources, segmented
from volatility3.framework.symbols import native

vollog = logging.getLogger(__name__)


class VmwareFormatException(exceptions.LayerException):
    """Thrown when an error occurs with the underlying VMware vmem file format."""


class VmwareLayer(segmented.SegmentedLayer):
    header_structure = "<4sII"
    group_structure = "64sQQ"

    def __init__(
        self,
        context: interfaces.context.ContextInterface,
        config_path: str,
        name: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        # Construct these so we can use self.config
        self._context = context
        self._config_path = config_path
        self._page_size = 0x1000
        self._base_layer, self._meta_layer = (
            self.config["base_layer"],
            self.config["meta_layer"],
        )
        # Then call the super, which will call load_segments (which needs the base_layer before it'll work)
        super().__init__(context, config_path=config_path, name=name, metadata=metadata)

    def _load_segments(self) -> None:
        """Loads up the segments from the meta_layer."""
        self._read_header()

    @staticmethod
    def _choose_type(size: int) -> str:
        return "vmware!unsigned int" if size == 4 else "vmware!unsigned long long"

    def _read_header(self) -> None:
        """Checks the vmware header to make sure it's valid."""
        if "vmware" not in self._context.symbol_space:
            self._context.symbol_space.append(
                native.NativeTable("vmware", native.std_ctypes)
            )

        meta_layer = self.context.layers.get(self._meta_layer, None)
        header_size = struct.calcsize(self.header_structure)
        data = meta_layer.read(0, header_size)
        magic, unknown, groupCount = struct.unpack(self.header_structure, data)
        if magic not in [
            b"\xD0\xBE\xD2\xBE",
            b"\xD1\xBA\xD1\xBA",
            b"\xD2\xBE\xD2\xBE",
            b"\xD3\xBE\xD3\xBE",
        ]:
            raise VmwareFormatException(
                self.name, f"Wrong magic bytes for Vmware layer: {repr(magic)}"
            )

        version = magic[0] & 0xF
        group_size = struct.calcsize(self.group_structure)

        groups = {}
        for group in range(groupCount):
            name, tag_location, _unknown = struct.unpack(
                self.group_structure,
                meta_layer.read(header_size + (group * group_size), group_size),
            )
            name = name.rstrip(b"\x00")
            groups[name] = tag_location
        memory = groups[b"memory"]

        tags_read = False
        offset = memory
        tags = {}
        index_len = self._context.symbol_space.get_type("vmware!unsigned int").size
        while not tags_read:
            flags = ord(meta_layer.read(offset, 1))
            name_len = ord(meta_layer.read(offset + 1, 1))
            tags_read = (flags == 0) and (name_len == 0)
            if not tags_read:
                name = self._context.object(
                    "vmware!string",
                    layer_name=self._meta_layer,
                    offset=offset + 2,
                    max_length=name_len,
                )
                indices_len = (flags >> 6) & 3
                indices = []
                for index in range(indices_len):
                    indices.append(
                        self._context.object(
                            "vmware!unsigned int",
                            offset=offset + name_len + 2 + (index * index_len),
                            layer_name=self._meta_layer,
                        )
                    )
                data_len = flags & 0x3F

                if data_len in [
                    62,
                    63,
                ]:  # Handle special data sizes that indicate a longer data stream
                    data_len = 4 if version == 0 else 8
                    # Read the size of the data
                    data_size = self._context.object(
                        self._choose_type(data_len),
                        layer_name=self._meta_layer,
                        offset=offset + 2 + name_len + (indices_len * index_len),
                    )
                    # Skip two bytes of padding (as it seems?)
                    # Read the actual data
                    data = self._context.object(
                        "vmware!bytes",
                        layer_name=self._meta_layer,
                        offset=offset
                        + 2
                        + name_len
                        + (indices_len * index_len)
                        + 2 * data_len
                        + 2,
                        length=data_size,
                    )
                    offset += (
                        2
                        + name_len
                        + (indices_len * index_len)
                        + 2 * data_len
                        + 2
                        + data_size
                    )
                else:  # Handle regular cases
                    data = self._context.object(
                        self._choose_type(data_len),
                        layer_name=self._meta_layer,
                        offset=offset + 2 + name_len + (indices_len * index_len),
                    )
                    offset += 2 + name_len + (indices_len * index_len) + data_len

                tags[(name, tuple(indices))] = (flags, data)

        if tags[("regionsCount", ())][1] == 0:
            raise VmwareFormatException(
                self.name, "VMware VMEM is not split into regions"
            )
        for region in range(tags[("regionsCount", ())][1]):
            offset = tags[("regionPPN", (region,))][1] * self._page_size
            mapped_offset = tags[("regionPageNum", (region,))][1] * self._page_size
            length = tags[("regionSize", (region,))][1] * self._page_size
            self._segments.append((offset, mapped_offset, length, length))

    @property
    def dependencies(self) -> List[str]:
        return [self._base_layer, self._meta_layer]

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        """This vmware translation layer always requires a separate metadata
        layer."""
        return [
            requirements.TranslationLayerRequirement(name="base_layer", optional=False),
            requirements.TranslationLayerRequirement(name="meta_layer", optional=False),
        ]


class VmwareStacker(interfaces.automagic.StackerLayerInterface):
    stack_order = 20

    @classmethod
    def stack(
        cls,
        context: interfaces.context.ContextInterface,
        layer_name: str,
        progress_callback: constants.ProgressCallback = None,
    ) -> Optional[interfaces.layers.DataLayerInterface]:
        """Attempt to stack this based on the starting information."""
        memlayer = context.layers[layer_name]
        if not isinstance(memlayer, physical.FileLayer):
            return None
        location = memlayer.location
        if location.endswith(".vmem"):
            vmss = location[:-5] + ".vmss"
            vmsn = location[:-5] + ".vmsn"
            current_layer_name = context.layers.free_layer_name("VmwareMetaLayer")
            current_config_path = interfaces.configuration.path_join(
                "automagic", "layer_stacker", "stack", current_layer_name
            )

            vmss_success = False
            with contextlib.suppress(IOError):
                with resources.ResourceAccessor().open(vmss) as fp:
                    _ = fp.read(10)
                context.config[
                    interfaces.configuration.path_join(current_config_path, "location")
                ] = vmss
                context.layers.add_layer(
                    physical.FileLayer(context, current_config_path, current_layer_name)
                )
                vmss_success = True

            vmsn_success = False
            if not vmss_success:
                with contextlib.suppress(IOError):
                    _ = resources.ResourceAccessor().open(vmsn).read(10)
                    context.config[
                        interfaces.configuration.path_join(
                            current_config_path, "location"
                        )
                    ] = vmsn
                    context.layers.add_layer(
                        physical.FileLayer(
                            context, current_config_path, current_layer_name
                        )
                    )
                    vmsn_success = True

            vollog.log(
                constants.LOGLEVEL_VVVV,
                f"Metadata found: VMSS ({vmss_success}) or VMSN ({vmsn_success})",
            )

            if not vmss_success and not vmsn_success:
                vollog.warning(
                    f"No metadata file alongside VMEM file! A VMSS or VMSN file is required to correctly process a VMEM file. These should be placed in the same directory with the same file name, e.g. sample.vmem and sample.vmsn.",
                )
                return None
            new_layer_name = context.layers.free_layer_name("VmwareLayer")
            context.config[
                interfaces.configuration.path_join(current_config_path, "base_layer")
            ] = layer_name
            context.config[
                interfaces.configuration.path_join(current_config_path, "meta_layer")
            ] = current_layer_name
            new_layer = VmwareLayer(context, current_config_path, new_layer_name)
            return new_layer
        return None
