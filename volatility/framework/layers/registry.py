from volatility.framework import interfaces, exceptions, constants
from volatility.framework.configuration import requirements
from volatility.framework.configuration.requirements import IntRequirement
from volatility.framework.interfaces.configuration import TranslationLayerRequirement


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
        self._hive = self.context.object(self._table_name + constants.BANG + "_CMHIVE", self._base_layer,
                                         self._hive_offset)
        # TODO: Check the checksum

        self._base_block = self._hive.Hive.BaseBlock.dereference()

        self._minaddr = 0
        self._maxaddr = self._base_block.Length

        self.mapping(self._base_block.RootCell, length = 2)

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
        if (offset > self._maxaddr):
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

        while length > 0:
            hbin_offset = self._translate(self._mask(offset, 32, 12))
            hbin = self.context.object(self._table_name + constants.BANG + "_HBIN",
                                       offset = hbin_offset,
                                       layer_name = self._base_layer)
            if hbin.Signature != 'hbin':
                raise RegistryFormatException("HBIN header not found")
            print(hex(hbin.Size))
            suboffset = self._translate(offset)
        print("MAPPED to", hex(suboffset))

        print(self.context.memory[self._base_layer].read(0xc6201000, 0x100))

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
