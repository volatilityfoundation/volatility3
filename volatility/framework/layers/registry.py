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

    @property
    def root_cell(self):
        return self._base_block.RootCell

    def get_cell(self, cell_offset):
        offset = self._translate(cell_offset)
        # This should be an _HCELL, but they don't exist in half the IFF files we've got.
        # Instead we pull out the cell (but current ignore the size)
        # TODO: Fix all of this, all of it, every last bit.
        return self._context.object(symbol = self._table_name + constants.BANG + "_CELL_DATA",
                                    offset = offset + 4,
                                    layer_name = self._base_layer)

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

        response = []
        while length > 0:
            # Try using the symbol first
            hbin_offset = self._translate(self._mask(offset, 31, 12))
            try:
                hbin_size = self.context.object(self._table_name + constants.BANG + "_HBIN",
                                                offset = hbin_offset,
                                                layer_name = self._base_layer).Size
            except exceptions.SymbolError:
                # TODO: Find the correct symbol to get this directly
                hbin_size = self.context.object(self._table_name + constants.BANG + "unsigned long",
                                                offset = hbin_offset + 8,
                                                layer_name = self._base_layer)

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
