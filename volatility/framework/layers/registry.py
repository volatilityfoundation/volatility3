import logging
import os.path as os_path
import typing

from volatility.framework import constants, exceptions, interfaces, objects
from volatility.framework.configuration import requirements
from volatility.framework.configuration.requirements import IntRequirement
from volatility.framework.interfaces.configuration import TranslationLayerRequirement
from volatility.framework.symbols import intermed

vollog = logging.getLogger(__name__)


class RegistryFormatException(exceptions.LayerException):
    """Thrown when an error occurs with the underlying Registry file format"""


class RegistryInvalidIndex(exceptions.LayerException):
    """Thrown when an index that doesn't exist or can't be found occurs"""


class RegistryHive(interfaces.layers.TranslationLayerInterface):
    def __init__(self,
                 context: interfaces.context.ContextInterface,
                 config_path: str,
                 name: str,
                 os: str = "Unknown") -> None:
        super().__init__(context, config_path, name, os)

        self._base_layer = self.config["base_layer"]
        self._hive_offset = self.config["hive_offset"]
        self._table_name = self.config["nt_symbols"]

        self._reg_table_name = context.symbol_space.free_table_name("registry")

        reg_path = "file://" + os_path.join(os_path.dirname(__file__), '..', 'symbols', 'windows', 'reg.json')
        table = intermed.IntermediateSymbolTable(context = context, config_path = config_path,
                                                 name = self._reg_table_name, isf_url = reg_path)
        context.symbol_space.append(table)

        self.hive = self.context.object(self._table_name + constants.BANG + "_CMHIVE", self._base_layer,
                                        self._hive_offset).Hive

        # TODO: Check the checksum
        if self.hive.Signature != 0xbee0bee0:
            raise RegistryFormatException(
                "Registry hive at {} does not have a valid signature".format(self._hive_offset))

        self._base_block = self.hive.BaseBlock.dereference()

        self._minaddr = 0
        self._maxaddr = self._base_block.Length

        if self._base_block.Length <= 0:
            raise exceptions.StructureException(
                "Invalid registry base_block length: {}".format(self._base_block.Length))

    @property
    def hive_offset(self) -> int:
        return self._hive_offset

    @property
    def address_mask(self) -> int:
        """Return a mask that allows for the volatile bit to be set"""
        return super().address_mask | 0x80000000

    @property
    def root_cell_offset(self) -> int:
        """Returns the offset for the root cell in this hive"""
        return self._base_block.RootCell

    def get_cell(self, cell_offset: int) -> 'objects.Struct':
        """Returns the appropriate Cell value for a cell offset"""
        # This would be an _HCELL containing CELL_DATA, but to save time we skip the size of the HCELL
        cell = self._context.object(symbol = self._table_name + constants.BANG + "_CELL_DATA", offset = cell_offset + 4,
                                    layer_name = self.name)
        return cell

    def get_node(self, cell_offset: int) -> 'objects.Struct':
        """Returns the appropriate Node, interpreted from the Cell based on its Signature"""
        cell = self.get_cell(cell_offset)
        signature = cell.cast('string', max_length = 2, encoding = 'latin-1')
        if signature == 'nk':
            return cell.u.KeyNode
        elif signature == 'sk':
            return cell.u.KeySecurity
        elif signature == 'vk':
            return cell.u.KeyValue
        elif signature == 'db':
            # Big Data
            return cell.u.ValueData
        elif signature == 'lf' or signature == 'lh' or signature == 'ri':
            # Fast Leaf, Hash Leaf, Index Root
            return cell.u.KeyIndex
        else:
            # It doesn't matter that we use KeyNode, we're just after the first two bytes
            vollog.debug(
                "Unknown Signature {} (0x{:x}) at offset {}".format(signature, cell.u.KeyNode.Signature, cell_offset))
            return cell

    def get_key(self, key: str, return_list: bool = False) -> interfaces.objects.ObjectInterface:
        """Gets a specific registry key by key path"""
        node_key = self.get_node(self.root_cell_offset) if not return_list else [self.get_node(self.root_cell_offset)]
        if key.endswith("\\"):
            key = key[:-1]
        key_array = key.split('\\')
        found_key = []  # type: typing.List[str]
        while key_array and node_key:
            subkeys = node_key.get_subkeys() if not return_list else node_key[-1].get_subkeys()
            for subkey in subkeys:
                if subkey.get_name() == key_array[0]:
                    node_key = subkey if not return_list else node_key + [subkey]
                    found_key, key_array = found_key + [key_array[0]], key_array[1:]
                    break
            else:
                node_key = None
        if not node_key:
            raise KeyError("Key {} not found under {}", key_array[0], '\\'.join(found_key))
        return node_key

    def visit_nodes(self,
                    visitor: typing.Callable[[objects.Struct], None],
                    node: typing.Optional[objects.Struct] = None) -> None:
        """Applies a callable (visitor) to all nodes within the registry tree from a given node"""
        if not node:
            node = self.get_node(self.root_cell_offset)
        visitor(node)
        for node in node.get_subkeys():
            self.visit_nodes(visitor, node)

    @staticmethod
    def _mask(value: int, high_bit: int, low_bit: int) -> int:
        """Returns the bits of a value between highbit and lowbit inclusive"""
        high_mask = (2 ** (high_bit + 1)) - 1
        low_mask = (2 ** low_bit) - 1
        mask = (high_mask ^ low_mask)
        # print(high_bit, low_bit, bin(mask), bin(value))
        return value & mask

    @classmethod
    def get_requirements(cls) -> typing.List[interfaces.configuration.RequirementInterface]:
        return [IntRequirement(name = 'hive_offset', description = '', default = 0, optional = False),
                requirements.SymbolRequirement(name = "nt_symbols", description = "Windows OS"),
                TranslationLayerRequirement(name = 'base_layer', optional = False)]

    def _translate(self, offset: int) -> int:
        """Translates a single cell index to a cell memory offset and the suboffset within it"""

        # Ignore the volatile bit when determining maxaddr validity
        if (offset & 0x7fffffff > self._maxaddr):
            raise RegistryInvalidIndex("Mapping request for value greater than maxaddr")

        volatile = self._mask(offset, 31, 31) >> 31
        storage = self.hive.Storage[volatile]
        dir_index = self._mask(offset, 30, 21) >> 21
        table_index = self._mask(offset, 20, 12) >> 12
        suboffset = self._mask(offset, 11, 0) >> 0

        table = storage.Map.Directory[dir_index]
        entry = table.Table[table_index]
        return entry.get_block_offset() + suboffset

    def mapping(self,
                offset: int,
                length: int,
                ignore_errors: bool = False) -> typing.Iterable[typing.Tuple[int, int, int, str]]:

        # TODO: Check the offset and offset + length are not outside the norms
        if (length < 0):
            raise ValueError("Mapping length of RegistryHive must be positive or zero")

        response = []
        while length > 0:
            # Try using the symbol first
            hbin_offset = self._translate(self._mask(offset, 31, 12))
            hbin = self.context.object(self._reg_table_name + constants.BANG + "_HBIN",
                                       offset = hbin_offset, layer_name = self._base_layer)

            # Now get the cell's offset and figure out if it goes outside the bin
            # We could use some invariants such as whether cells always fit within a bin?
            translated_offset = self._translate(offset)
            if translated_offset + length > hbin_offset + hbin.Size:
                # Generally suggests the hbin is a large (larger than a page) bin
                # In which case, hunt backwards for the right hbin header and check the size again
                while hbin.Signature.cast("string", max_length = 4, encoding = "latin-1") != 'hbin':
                    hbin_offset = hbin_offset - 0x1000
                    hbin = self.context.object(self._reg_table_name + constants.BANG + "_HBIN",
                                               offset = hbin_offset, layer_name = self._base_layer)
                    if translated_offset + length > hbin_offset + hbin.Size:
                        raise RegistryFormatException("Cell address outside expected HBIN")
            response.append((offset, translated_offset, length, self._base_layer))
            length -= length
        return response

    @property
    def dependencies(self) -> typing.List[str]:
        """Returns a list of layer names that this layer translates onto"""
        return [self.config['base_layer']]

    def is_valid(self, offset: int, length: int = 1) -> bool:
        """Returns a boolean based on whether the offset is valid or not"""
        # TODO: Fix me
        return True

    @property
    def minimum_address(self) -> int:
        return self._minaddr

    @property
    def maximum_address(self) -> int:
        return self._maxaddr
