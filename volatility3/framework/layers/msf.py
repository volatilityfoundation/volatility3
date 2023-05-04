# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
import math
from typing import Optional, Dict, Any, List, Iterable, Tuple

from volatility3.framework import interfaces, constants, exceptions
from volatility3.framework.configuration import requirements
from volatility3.framework.layers import linear
from volatility3.framework.objects import utility
from volatility3.framework.symbols import intermed


class PDBFormatException(exceptions.LayerException):
    """Thrown when an error occurs with the underlying MSF file format."""


class PdbMultiStreamFormat(linear.LinearlyMappedLayer):
    _headers = {
        "MSF_HDR": "Microsoft C/C++ program database 2.00\r\n\x1a\x4a\x47",
        "BIG_MSF_HDR": "Microsoft C/C++ MSF 7.00\r\n\x1a\x44\x53",
    }

    def __init__(
        self,
        context: "interfaces.context.ContextInterface",
        config_path: str,
        name: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__(context, config_path, name, metadata)
        self._base_layer = self.config["base_layer"]

        self._pdb_symbol_table = intermed.IntermediateSymbolTable.create(
            context, self._config_path, "windows", "pdb"
        )
        response = self._check_header()
        if response is None:
            raise PDBFormatException(name, "Could not find a suitable header")
        self._version, self._header = response
        self._streams: Dict[int, str] = {}

    @property
    def pdb_symbol_table(self) -> str:
        return self._pdb_symbol_table

    def read_streams(self):
        # Shortcut in case they've already been read
        if self._streams:
            return

        # Recover the root table, by recovering the root table index table...
        module = self.context.module(self.pdb_symbol_table, self._base_layer, offset=0)
        entry_size = module.get_type("unsigned long").size

        root_table_num_pages = math.ceil(
            self._header.StreamInfo.StreamInfoSize / self._header.PageSize
        )
        root_index_size = math.ceil(
            (root_table_num_pages * entry_size) / self._header.PageSize
        )
        root_index = module.object(
            object_type="array",
            offset=self._header.vol.size,
            count=root_index_size,
            subtype=module.get_type("unsigned long"),
        )
        root_index_layer_name = self.create_stream_from_pages(
            "root_index",
            self._header.StreamInfo.StreamInfoSize,
            [x for x in root_index],
        )

        module = self.context.module(
            self.pdb_symbol_table, root_index_layer_name, offset=0
        )
        root_pages = module.object(
            object_type="array",
            offset=0,
            count=root_table_num_pages,
            subtype=module.get_type("unsigned long"),
        )
        root_layer_name = self.create_stream_from_pages(
            "root", self._header.StreamInfo.StreamInfoSize, [x for x in root_pages]
        )

        module = self.context.module(self.pdb_symbol_table, root_layer_name, offset=0)
        num_streams = module.object(object_type="unsigned long", offset=0)
        stream_sizes = module.object(
            object_type="array",
            offset=entry_size,
            count=num_streams,
            subtype=module.get_type("unsigned long"),
        )

        current_offset = (num_streams + 1) * entry_size

        for stream in range(num_streams):
            list_size = math.ceil(stream_sizes[stream] / self.page_size)
            if list_size == 0 or stream_sizes[stream] == 0xFFFFFFFF:
                self._streams[stream] = None
            else:
                stream_page_list = module.object(
                    object_type="array",
                    offset=current_offset,
                    count=list_size,
                    subtype=module.get_type("unsigned long"),
                )
                current_offset += list_size * entry_size
                self._streams[stream] = self.create_stream_from_pages(
                    "stream" + str(stream),
                    stream_sizes[stream],
                    [x for x in stream_page_list],
                )

    def create_stream_from_pages(
        self, stream_name: str, maximum_size: int, pages: List[int]
    ) -> str:
        # Construct a root layer based on a number of pages
        layer_name = self.name + "_" + stream_name
        path_join = interfaces.configuration.path_join
        config_path = path_join(self.config_path, stream_name)
        self.context.config[path_join(config_path, "base_layer")] = self.name
        self.context.config[path_join(config_path, "pages")] = pages
        self.context.config[path_join(config_path, "maximum_size")] = maximum_size
        layer = PdbMSFStream(self.context, config_path, layer_name)
        self.context.layers.add_layer(layer)
        return layer_name

    def _check_header(self) -> Optional[Tuple[str, interfaces.objects.ObjectInterface]]:
        """Verifies the header of the PDB file and returns the version of the
        file."""
        for header in self._headers:
            header_type = self.pdb_symbol_table + constants.BANG + header
            current_header = self.context.object(header_type, self._base_layer, 0)
            if utility.array_to_string(current_header.Magic) == self._headers[header]:
                if not (
                    current_header.PageSize < 0x100
                    or current_header.PageSize > (128 * 0x10000)
                ):
                    return header, current_header
        return None

    @property
    def page_size(self):
        return self._header.PageSize

    @property
    def dependencies(self) -> List[str]:
        """Returns a list of the lower layers that this layer is dependent
        upon."""
        return [self._base_layer]

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.TranslationLayerRequirement(name="base_layer", optional=False)
        ]

    @property
    def maximum_address(self) -> int:
        return self.context.layers[self._base_layer].maximum_address

    @property
    def minimum_address(self) -> int:
        return self.context.layers[self._base_layer].minimum_address

    def is_valid(self, offset: int, length: int = 1) -> bool:
        return self.context.layers[self._base_layer].is_valid(offset, length)

    def mapping(
        self, offset: int, length: int, ignore_errors: bool = False
    ) -> Iterable[Tuple[int, int, int, int, str]]:
        yield offset, length, offset, length, self._base_layer

    def get_stream(self, index) -> Optional["PdbMSFStream"]:
        self.read_streams()
        if index not in self._streams:
            raise PDBFormatException(self.name, "Stream not present")
        if self._streams[index]:
            layer = self.context.layers[self._streams[index]]
            if isinstance(layer, PdbMSFStream):
                return layer
        return None


class PdbMSFStream(linear.LinearlyMappedLayer):
    def __init__(
        self,
        context: "interfaces.context.ContextInterface",
        config_path: str,
        name: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__(context, config_path, name, metadata)
        self._base_layer = self.config["base_layer"]
        self._pages = self.config.get("pages", None)
        self._pages_len = len(self._pages)
        if not self._pages:
            raise PDBFormatException(name, "Invalid/no pages specified")
        if not isinstance(self._pdb_layer, PdbMultiStreamFormat):
            raise TypeError("Base Layer must be a PdbMultiStreamFormat layer")

    @property
    def pdb_symbol_table(self) -> Optional[str]:
        layer = self._context.layers[self._base_layer]
        if isinstance(layer, PdbMultiStreamFormat):
            return layer.pdb_symbol_table
        else:
            return None

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ListRequirement(
                name="pages", element_type=int, min_elements=1
            ),
            requirements.TranslationLayerRequirement(name="base_layer"),
            requirements.IntRequirement(name="maximum_size"),
        ]

    def mapping(
        self, offset: int, length: int, ignore_errors: bool = False
    ) -> Iterable[Tuple[int, int, int, int, str]]:
        returned = 0
        page_size = self._pdb_layer.page_size
        while length > 0:
            page = math.floor((offset + returned) / page_size)
            page_position = (offset + returned) % page_size
            chunk_size = min(page_size - page_position, length)
            if page >= self._pages_len:
                if not ignore_errors:
                    raise exceptions.InvalidAddressException(
                        layer_name=self.name, invalid_address=offset + returned
                    )
            else:
                yield offset + returned, chunk_size, (
                    self._pages[page] * page_size
                ) + page_position, chunk_size, self._base_layer
            returned += chunk_size
            length -= chunk_size

    @property
    def dependencies(self) -> List[str]:
        return [self._base_layer]

    def is_valid(self, offset: int, length: int = 1) -> bool:
        return self.context.layers[self._base_layer].is_valid(offset, length)

    @property
    def minimum_address(self) -> int:
        return 0

    @property
    def maximum_address(self) -> int:
        return self.config.get(
            "maximum_size", len(self._pages) * self._pdb_layer.page_size
        )

    @property
    def _pdb_layer(self) -> PdbMultiStreamFormat:
        if self._base_layer not in self._context.layers:
            raise PDBFormatException(
                self._base_layer,
                f"No PdbMultiStreamFormat layer found: {self._base_layer}",
            )
        result = self._context.layers[self._base_layer]
        if isinstance(result, PdbMultiStreamFormat):
            return result
        raise TypeError("Base layer is not PdbMultiStreamFormat")
