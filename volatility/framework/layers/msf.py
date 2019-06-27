import math
from typing import Optional, Dict, Any, List, Iterable, Tuple

from volatility.framework import interfaces, constants
from volatility.framework.configuration import requirements
from volatility.framework.objects import utility
from volatility.framework.symbols import intermed


class PdbMSF(interfaces.layers.TranslationLayerInterface):
    headers = {
        "MSF_HDR": "Microsoft C/C++ program database 2.00\r\n\x1a\x4a\x47",
        "BIG_MSF_HDR": "Microsoft C/C++ MSF 7.00\r\n\x1a\x44\x53",
    }

    def __init__(self,
                 context: 'interfaces.context.ContextInterface',
                 config_path: str,
                 name: str,
                 metadata: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(context, config_path, name, metadata)
        self._base_layer = self.config["base_layer"]

        self._pdb_table_name = intermed.IntermediateSymbolTable.create(context, self._config_path, 'windows', 'pdb')
        response = self._check_header()
        if response is None:
            raise ValueError("Could not find a suitable header")
        self._version, self._header = response
        self._streams = {}  # type: Dict[int, Optional[PdbMSFStream]]

    def read_streams(self):
        # Shortcut in case they've already been read
        if self._streams:
            return

        # Recover the root table, by recovering the root table index table...
        module = self.context.module(self._pdb_table_name, self._base_layer, offset = 0)
        entry_size = module.get_type("unsigned long").size

        root_table_num_pages = math.ceil(self._header.StreamInfo.StreamInfoSize / self._header.PageSize)
        root_index_size = math.ceil((root_table_num_pages * entry_size) / self._header.PageSize)
        root_index = module.object(
            type_name = "array",
            layer_name = self._base_layer,
            offset = self._header.vol.size,
            count = root_index_size,
            subtype = module.get_type("unsigned long"))
        root_index_layer_name = self.create_stream_from_pages("root_index", [x for x in root_index])

        module = self.context.module(self._pdb_table_name, root_index_layer_name, offset = 0)
        root_pages = self.context.object(
            symbol = self._pdb_table_name + constants.BANG + "array",
            layer_name = root_index_layer_name,
            offset = 0,
            count = root_table_num_pages,
            subtype = module.get_type("unsigned long"))
        root_layer_name = self.create_stream_from_pages("root", [x for x in root_pages])

        module = self.context.module(self._pdb_table_name, root_layer_name, offset = 0)
        num_streams = module.object(type_name = "unsigned long", offset = 0)
        stream_sizes = module.object(
            type_name = "array", offset = entry_size, count = num_streams, subtype = module.get_type("unsigned long"))

        current_offset = (num_streams + 1) * entry_size

        for stream in range(num_streams):
            list_size = math.ceil(stream_sizes[stream] / self.page_size)
            if list_size:
                stream_page_list = module.object(
                    type_name = "array",
                    offset = current_offset,
                    count = list_size,
                    subtype = module.get_type("unsigned long"))
                current_offset += (list_size * entry_size)
                self._streams[stream] = self.create_stream_from_pages("stream", [x for x in stream_page_list])
            else:
                self._streams[stream] = None

    def create_stream_from_pages(self, stream_name: str, pages: List[int]) -> str:
        # Construct a root layer based on a number of pages
        layer_name = self.context.layers.free_layer_name(self.name + "_" + stream_name)
        path_join = interfaces.configuration.path_join
        config_path = path_join(self.config_path, stream_name)
        self.context.config[path_join(config_path, 'base_layer')] = self.name
        self.context.config[path_join(config_path, 'pages')] = pages
        layer = PdbMSFStream(self.context, config_path, layer_name)
        self.context.layers.add_layer(layer)
        return layer_name

    def _check_header(self) -> Optional[Tuple[str, interfaces.objects.ObjectInterface]]:
        """Verifies the header of the PDB file and returns the version of the file"""
        for header in self.headers:
            header_type = self._pdb_table_name + constants.BANG + header
            current_header = self.context.object(header_type, self._base_layer, 0)
            if utility.array_to_string(current_header.Magic) == self.headers[header]:
                if not (current_header.PageSize < 0x100 or current_header.PageSize > (128 * 0x10000)):
                    return header, current_header
        return None

    @property
    def page_size(self):
        return self._header.PageSize

    @property
    def dependencies(self) -> List[str]:
        """Returns a list of the lower layers that this layer is dependent upon"""
        return [self._base_layer]

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [requirements.TranslationLayerRequirement(name = 'base_layer', optional = False)]

    @property
    def maximum_address(self) -> int:
        return self.context.layers[self._base_layer].maximum_address

    @property
    def minimum_address(self) -> int:
        return self.context.layers[self._base_layer].minimum_address

    def is_valid(self, offset: int, length: int = 1) -> bool:
        return self.context.layers[self._base_layer].is_valid(offset, length)

    def mapping(self, offset: int, length: int, ignore_errors: bool = False) -> Iterable[Tuple[int, int, int, str]]:
        yield (offset, offset, length, self._base_layer)

    def get_stream(self, index) -> Optional['PdbMSFStream']:
        self.read_streams()
        if index not in self._streams:
            raise ValueError("Stream not present")
        if self._streams[index]:
            return self.context.layers[self._streams[index]]


class PdbMSFStream(interfaces.layers.TranslationLayerInterface):

    def __init__(self,
                 context: 'interfaces.context.ContextInterface',
                 config_path: str,
                 name: str,
                 metadata: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(context, config_path, name, metadata)
        self._base_layer = self.config["base_layer"]
        self._pages = self.config.get("pages", None)
        if not self._pages:
            raise ValueError("Invalid/no pages specified")
        if not isinstance(self._pdb_layer, PdbMSF):
            raise TypeError("Base Layer must be a PdbMSF layer")

    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [requirements.ListRequirement(name = 'pages', element_type = int, min_elements = 1)]

    def mapping(self, offset: int, length: int, ignore_errors: bool = False) -> Iterable[Tuple[int, int, int, str]]:
        returned = 0
        page_size = self._pdb_layer.page_size
        while length > 0:
            page = math.floor((offset + returned) / page_size)
            page_position = ((offset + returned) % page_size)
            chunk_size = min(page_size - page_position, length)
            yield (offset + returned, (self._pages[page] * page_size) + page_position, chunk_size, self._base_layer)
            returned += chunk_size
            length -= chunk_size

    @property
    def dependencies(self) -> List[str]:
        return [self._base_layer]

    def is_valid(self, offset: int, length: int = 1) -> bool:
        return self.minimum_address <= offset and offset + length < self.maximum_address

    @property
    def minimum_address(self) -> int:
        return 0

    @property
    def maximum_address(self) -> int:
        return len(self._pages) * self._pdb_layer.page_size

    @property
    def _pdb_layer(self) -> Optional[PdbMSF]:
        return self._context.layers.get(self._base_layer, None)
