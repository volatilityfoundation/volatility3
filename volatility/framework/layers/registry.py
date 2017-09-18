import os.path as os_path

from volatility.framework import constants, exceptions, interfaces
from volatility.framework.configuration import requirements
from volatility.framework.configuration.requirements import IntRequirement
from volatility.framework.interfaces.configuration import TranslationLayerRequirement
from volatility.framework.symbols import intermed


class RegistryFormatException(exceptions.LayerException):
    """Thrown when an error occurs with the underlying Registry file format"""


class RegistryInvalidIndex(exceptions.LayerException):
    """Thrown when an index that doesn't exist or can't be found occurs"""


class RegistryHive(interfaces.layers.TranslationLayerInterface):
    def __init__(self, context, config_path, name, os = "Unknown"):
        super().__init__(context, config_path, name, os)

        self._base_layer = self.config["base_layer"]
        self._hive_offset = self.config["hive_offset"]
        self._table_name = self.config["ntkrnlmp"]

        self._reg_table_name = context.symbol_space.free_table_name("registry")

        reg_path = "file://" + os_path.join(os_path.dirname(__file__), '..', 'symbols', 'windows', 'reg.json')
        table = intermed.IntermediateSymbolTable(context = context, config_path = config_path,
                                                 name = self._reg_table_name, isf_filepath = reg_path)
        context.symbol_space.append(table)

        self._hive = self.context.object(self._table_name + constants.BANG + "_CMHIVE", self._base_layer,
                                         self._hive_offset)

        # TODO: Check the checksum

        self._base_block = self._hive.Hive.BaseBlock.dereference()

        self._minaddr = 0
        self._maxaddr = self._base_block.Length

        # print("MAPPING", self.mapping(self._base_block.RootCell, length = 2))

    @property
    def address_mask(self):
        """Return a mask that allows for the volatile bit to be set"""
        return super().address_mask | 0x80000000

    @property
    def root_cell(self):
        return self._base_block.RootCell

    def get_cell(self, cell_offset):
        offset = self._translate(cell_offset)
        print(repr(self._context.memory[self._base_layer].read(offset, 0x100)))
        cell = self._context.object(symbol = self._table_name + constants.BANG + "_CM_CACHED_VALUE_INDEX",
                                    offset = offset, layer_name = self._base_layer).Data.CellData
        signature = cell.u.KeyNode.Signature.cast("string", max_length = 2)
        if signature == 'nk':
            return cell.u.KeyNode
        elif signature == 'sk':
            return cell.u.KeySecurity
        elif signature == 'vk':
            return cell.u.KeyValue
        elif signature == 'db':
            return cell.u.ValueData
        elif signature == 'lf':
            return cell.u.KeyIndex

        else:
            print("Unknown Signature", signature)
            if signature == '':
                return cell.u.KeyList
            if signature == '':
                return cell.u.KeyString

    def get_key(self, key_path):
        key_path_array = key_path.split("/")

    def subkeys(self, key):
        if not key.vol.type_name.endswith(constants.BANG + '_CM_KEY_NODE'):
            raise TypeError("Key for subkeys must be a _CM_KEY_NODE")
        for index in range(2):
            subkey_node = self.get_cell(key.SubKeyLists[index])
            if subkey_node.vol.type_name.endswith(constants.BANG + '_CM_KEY_INDEX'):
                pass

    @staticmethod
    def _mask(value, high_bit, low_bit):
        """Returns the bits of a value between highbit and lowbit inclusive"""
        high_mask = (2 ** (high_bit + 1)) - 1
        low_mask = (2 ** low_bit) - 1
        mask = (high_mask ^ low_mask)
        # print(high_bit, low_bit, bin(mask), bin(value))
        return value & mask

    def get_requirements(cls):
        return [IntRequirement(name = 'hive_offset', description = '', default = 0, optional = False),
                requirements.SymbolRequirement(name = "ntkrnlmp", description = "Windows OS"),
                TranslationLayerRequirement(name = 'base_layer', optional = False)]

    def _translate(self, offset):
        """Translates a single cell index to a cell memory offset and the suboffset within it"""

        # Ignore the volatile bit when determining maxaddr validity
        if (offset & 0x7fffffff > self._maxaddr):
            raise RegistryInvalidIndex("Mapping request for value greater than maxaddr")

        volatile = self._mask(offset, 31, 31) >> 31
        storage = self._hive.Hive.Storage[volatile]
        dir_index = self._mask(offset, 30, 21) >> 21
        table_index = self._mask(offset, 20, 12) >> 12
        suboffset = self._mask(offset, 11, 0) >> 0

        table = storage.Map.Directory[dir_index]
        entry = table.Table[table_index]
        return entry.BlockAddress + suboffset

    def mapping(self, offset, length, ignore_errors = False):

        # TODO: Check the offset and offset + length are not outside the norms
        if (length < 0):
            raise ValueError("Mapping length of RegistryHive must be positive or zero")

        response = []
        while length > 0:
            # Try using the symbol first
            hbin_offset = self._translate(self._mask(offset, 31, 12))
            hbin_size = self.context.object(self._reg_table_name + constants.BANG + "_HBIN",
                                            offset = hbin_offset, layer_name = self._base_layer).Size

            # Now get the cell's offset and figure out if it goes outside the bin
            # We could use some invariants such as whether cells always fit within a bin?
            translated_offset = self._translate(offset)
            if translated_offset + length > hbin_offset + hbin_size:
                usable_size = (hbin_offset + hbin_size - translated_offset)
                response.append((offset, translated_offset, usable_size, self._base_layer))
                length -= usable_size
                offset += usable_size
            else:
                response.append((offset, translated_offset, length, self._base_layer))
                length -= length
        return response

    @property
    def dependencies(self):
        """Returns a list of layer names that this layer translates onto"""
        return [self.config['base_layer']]

    def is_valid(self, offset, length = 1):
        """Returns a boolean based on whether the offset is valid or not"""
        # TODO: Fix me
        return True

    @property
    def minimum_address(self):
        return self._minaddr

    @property
    def maximum_address(self):
        return self._maxaddr
