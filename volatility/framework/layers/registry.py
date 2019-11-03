# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

import logging
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple, Union

from volatility.framework import constants, exceptions, interfaces, objects
from volatility.framework.configuration import requirements
from volatility.framework.configuration.requirements import IntRequirement, TranslationLayerRequirement
from volatility.framework.exceptions import InvalidAddressException
from volatility.framework.layers import linear
from volatility.framework.symbols import intermed
from volatility.plugins.windows import pslist

vollog = logging.getLogger(__name__)


class RegistryFormatException(exceptions.LayerException):
    """Thrown when an error occurs with the underlying Registry file format."""


class RegistryInvalidIndex(exceptions.LayerException):
    """Thrown when an index that doesn't exist or can't be found occurs."""


class RegistryHive(linear.LinearlyMappedLayer):

    def __init__(self,
                 context: interfaces.context.ContextInterface,
                 config_path: str,
                 name: str,
                 metadata: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(context = context, config_path = config_path, name = name, metadata = metadata)

        self._base_layer = self.config["base_layer"]
        self._hive_offset = self.config["hive_offset"]
        self._table_name = self.config["nt_symbols"]

        self._reg_table_name = intermed.IntermediateSymbolTable.create(context, self._config_path, 'windows',
                                                                       'registry')

        cmhive = self.context.object(self._table_name + constants.BANG + "_CMHIVE", self._base_layer, self._hive_offset)
        self._cmhive_name = cmhive.get_name()
        self.hive = cmhive.Hive

        # TODO: Check the checksum
        if self.hive.Signature != 0xbee0bee0:
            raise RegistryFormatException(
                self.name, "Registry hive at {} does not have a valid signature".format(self._hive_offset))

        # Win10 17063 introduced the Registry process to map most hives.  Check
        # if it exists and update RegistryHive._base_layer
        for proc in pslist.PsList.list_processes(self.context, self.config['base_layer'], self.config['nt_symbols']):
            proc_name = proc.ImageFileName.cast("string", max_length = proc.ImageFileName.vol.count, errors = 'replace')
            if proc_name == "Registry" and proc.InheritedFromUniqueProcessId == 4:
                proc_layer_name = proc.add_process_layer()
                self._base_layer = proc_layer_name
                break

        self._base_block = self.hive.BaseBlock.dereference()

        self._minaddr = 0
        try:
            self._hive_maxaddr_non_volatile = self.hive.Storage[0].Length
            self._hive_maxaddr_volatile = self.hive.Storage[1].Length
            self._maxaddr = 0x80000000 | self._hive_maxaddr_volatile
            vollog.log(constants.LOGLEVEL_VVV, "Setting hive max address to {}".format(hex(self._maxaddr)))
        except exceptions.InvalidAddressException:
            self._hive_maxaddr_non_volatile = 0x7fffffff
            self._hive_maxaddr_volatile = 0x7fffffff
            self._maxaddr = 0x80000000 | self._hive_maxaddr_volatile
            vollog.log(constants.LOGLEVEL_VVV,
                       "Exception when setting hive max address, using {}".format(hex(self._maxaddr)))

    def _get_hive_maxaddr(self, volatile):
        return self._hive_maxaddr_volatile if volatile else self._hive_maxaddr_non_volatile

    def get_name(self) -> str:
        return self._cmhive_name or "[NONAME]"

    @property
    def hive_offset(self) -> int:
        return self._hive_offset

    @property
    def address_mask(self) -> int:
        """Return a mask that allows for the volatile bit to be set."""
        return super().address_mask | 0x80000000

    @property
    def root_cell_offset(self) -> int:
        """Returns the offset for the root cell in this hive."""
        try:
            if self._base_block.Signature.cast("string", max_length = 4, encoding = "latin-1") == 'regf':
                return self._base_block.RootCell
        except InvalidAddressException:
            pass
        return 0x20

    def get_cell(self, cell_offset: int) -> 'objects.StructType':
        """Returns the appropriate Cell value for a cell offset."""
        # This would be an _HCELL containing CELL_DATA, but to save time we skip the size of the HCELL
        cell = self._context.object(object_type = self._table_name + constants.BANG + "_CELL_DATA",
                                    offset = cell_offset + 4,
                                    layer_name = self.name)
        return cell

    def get_node(self, cell_offset: int) -> 'objects.StructType':
        """Returns the appropriate Node, interpreted from the Cell based on its
        Signature."""
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
            vollog.debug("Unknown Signature {} (0x{:x}) at offset {}".format(signature, cell.u.KeyNode.Signature,
                                                                             cell_offset))
            return cell

    def get_key(self, key: str, return_list: bool = False) -> Union[List[objects.StructType], objects.StructType]:
        """Gets a specific registry key by key path.

        return_list specifies whether the return result will be a single
        node (default) or a list of nodes from root to the current node
        (if return_list is true).
        """
        node_key = [self.get_node(self.root_cell_offset)]
        if key.endswith("\\"):
            key = key[:-1]
        key_array = key.split('\\')
        found_key = []  # type: List[str]
        while key_array and node_key:
            subkeys = node_key[-1].get_subkeys()
            for subkey in subkeys:
                # registry keys are not case sensitive so compare lowercase
                # https://msdn.microsoft.com/en-us/library/windows/desktop/ms724946(v=vs.85).aspx
                if subkey.get_name().lower() == key_array[0].lower():
                    node_key = node_key + [subkey]
                    found_key, key_array = found_key + [key_array[0]], key_array[1:]
                    break
            else:
                node_key = []
        if not node_key:
            raise KeyError("Key {} not found under {}", key_array[0], '\\'.join(found_key))
        if return_list:
            return node_key
        return node_key[-1]

    def visit_nodes(self, visitor: Callable[[objects.StructType], None],
                    node: Optional[objects.StructType] = None) -> None:
        """Applies a callable (visitor) to all nodes within the registry tree
        from a given node."""
        if not node:
            node = self.get_node(self.root_cell_offset)
        visitor(node)
        for node in node.get_subkeys():
            self.visit_nodes(visitor, node)

    @staticmethod
    def _mask(value: int, high_bit: int, low_bit: int) -> int:
        """Returns the bits of a value between highbit and lowbit inclusive."""
        high_mask = (2 ** (high_bit + 1)) - 1
        low_mask = (2 ** low_bit) - 1
        mask = (high_mask ^ low_mask)
        # print(high_bit, low_bit, bin(mask), bin(value))
        return value & mask

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            IntRequirement(name = 'hive_offset',
                           description = 'Offset within the base layer at which the hive lives',
                           default = 0,
                           optional = False),
            requirements.SymbolTableRequirement(name = "nt_symbols", description = "Windows kernel symbols"),
            TranslationLayerRequirement(name = 'base_layer',
                                        description = 'Layer in which the registry hive lives',
                                        optional = False)
        ]

    def _translate(self, offset: int) -> int:
        """Translates a single cell index to a cell memory offset and the
        suboffset within it."""

        # Ignore the volatile bit when determining maxaddr validity
        volatile = self._mask(offset, 31, 31) >> 31
        if offset & 0x7fffffff > self._get_hive_maxaddr(volatile):
            raise RegistryInvalidIndex(self.name, "Mapping request for value greater than maxaddr")

        storage = self.hive.Storage[volatile]
        dir_index = self._mask(offset, 30, 21) >> 21
        table_index = self._mask(offset, 20, 12) >> 12
        suboffset = self._mask(offset, 11, 0) >> 0

        table = storage.Map.Directory[dir_index]
        entry = table.Table[table_index]
        return entry.get_block_offset() + suboffset

    def mapping(self, offset: int, length: int, ignore_errors: bool = False) -> Iterable[Tuple[int, int, int, str]]:

        if length < 0:
            raise ValueError("Mapping length of RegistryHive must be positive or zero")

        # Return the translated offset without checking bounds within the HBIN.  The check runs into
        # issues when pages are swapped on large HBINs, and did not seem to find any errors on single page
        # HBINs while dramatically slowing performance.
        translated_offset = self._translate(offset)
        response = [(offset, translated_offset, length, self._base_layer)]
        return response

    @property
    def dependencies(self) -> List[str]:
        """Returns a list of layer names that this layer translates onto."""
        return [self.config['base_layer']]

    def is_valid(self, offset: int, length: int = 1) -> bool:
        """Returns a boolean based on whether the offset is valid or not."""
        # TODO: Fix me

        # Pass this to the lower layers for now
        return all([
            self.context.layers[layer].is_valid(offset, length)
            for (_, offset, length, layer) in self.mapping(offset, length)
        ])

    @property
    def minimum_address(self) -> int:
        return self._minaddr

    @property
    def maximum_address(self) -> int:
        return self._maxaddr
