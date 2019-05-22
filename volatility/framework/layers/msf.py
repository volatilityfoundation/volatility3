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
        self._version = self._check_header()

    def _check_header(self) -> Optional[str]:
        """Verifies the header of the PDB file and returns the version of the file"""
        for header in self.headers:
            header_type = self._pdb_table_name + constants.BANG + header
            current_header = self.context.object(header_type, self._base_layer, 0)
            if utility.array_to_string(current_header.Magic) == self.headers[header]:
                return header
        return None

    @property
    def dependencies(self) -> List[str]:
        """Returns a list of the lower layers that this layer is dependent upon"""
        return [self._base_layer]

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [requirements.TranslationLayerRequirement(name = 'base_layer', optional = False)]

    @property
    def maximum_address(self) -> int:
        return self.context.memory[self._base_layer].maximum_address

    @property
    def minimum_address(self) -> int:
        return self.context.memory[self._base_layer].minimum_address

    def is_valid(self, offset: int, length: int = 1) -> bool:
        return self.context.memory[self._base_layer].is_valid(offset, length)

    def mapping(self, offset: int, length: int, ignore_errors: bool = False) -> Iterable[Tuple[int, int, int, str]]:
        yield (offset, offset, length, self._base_layer)


class PdbMSFStream(interfaces.layers.TranslationLayerInterface):
    pass
