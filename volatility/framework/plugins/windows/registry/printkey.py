# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl_v1.0
#

import datetime
import logging
from typing import Generator, List, Sequence, Iterable, Optional

from volatility.framework import objects, renderers, exceptions, interfaces, constants
from volatility.framework.configuration import requirements
from volatility.framework.layers.registry import RegistryHive, RegistryFormatException
from volatility.framework.renderers import TreeGrid, conversion, format_hints
from volatility.framework.symbols.windows.extensions.registry import RegValueTypes
from volatility.plugins.windows.registry import hivelist

vollog = logging.getLogger(__name__)


class PrintKey(interfaces.plugins.PluginInterface):
    """Lists the registry keys under a hive or specific key value."""

    _version = (1, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.TranslationLayerRequirement(
                name = 'primary', description = 'Memory layer for the kernel', architectures = ["Intel32", "Intel64"]),
            requirements.SymbolTableRequirement(name = "nt_symbols", description = "Windows kernel symbols"),
            requirements.PluginRequirement(name = 'hivelist', plugin = hivelist.HiveList, version = (1, 0, 0)),
            requirements.IntRequirement(name = 'offset', description = "Hive Offset", default = None, optional = True),
            requirements.StringRequirement(
                name = 'key', description = "Key to start from", default = None, optional = True),
            requirements.BooleanRequirement(
                name = 'recurse', description = 'Recurses through keys', default = False, optional = True)
        ]

    @classmethod
    def key_iterator(cls, hive: RegistryHive, node_path: Sequence[objects.StructType] = None,
                     recurse: bool = False) -> Iterable[int, bool, datetime.datetime, str, bool, bytes]:
        """Walks through a set of nodes from a given node (last one in
        node_path). Avoids loops by not traversing into nodes already present
        in the node_path.

        Args:
            hive: The registry hive to walk
            node_path: The list of nodes that make up the
            recurse: Traverse down the node tree or stay only on the same level

        Yields:
            The depth, and a tuple of results (last write time, hive offset, type, path, name, data and volatile)
        """
        if not node_path:
            node_path = [hive.get_node(hive.root_cell_offset)]
        if not isinstance(node_path, list) or len(node_path) < 1:
            vollog.warning("Hive walker was not passed a valid node_path (or None)")
            return
        node = node_path[-1]
        if node.vol.type_name.endswith(constants.BANG + '_CELL_DATA'):
            raise RegistryFormatException("Encountered _CELL_DATA instead of _CM_KEY_NODE")
        key_path = node.get_key_path()
        last_write_time = conversion.wintime_to_datetime(node.LastWriteTime.QuadPart)

        for key_node in node.get_subkeys():
            result = (len(node_path), True, last_write_time, key_path, key_node.get_volatile(), key_node)
            yield result

            if recurse:
                if key_node.vol.offset not in [x.vol.offset for x in node_path]:
                    try:
                        sub_node_name = key_node.get_name()
                    except exceptions.InvalidAddressException as excp:
                        vollog.debug(excp)
                        continue

                    yield from cls.key_iterator(hive, node_path + [key_node], recurse = recurse)

        for value_node in node.get_values():
            result = (len(node_path), False, last_write_time, key_path, node.get_volatile(), value_node)
            yield result

    @classmethod
    def hive_iterator(cls,
                      context: interfaces.context.ContextInterface,
                      base_config_path: str,
                      layer_name: str,
                      symbol_table: str,
                      filter_string: Optional[str] = None,
                      hive_offsets: List[int] = None) -> Iterable[RegistryHive]:
        """Walks through a registry, hive by hive returning the constructed
        registry layer name.

        Args:
            context: The context to retrieve required elements (layers, symbol tables) from
            layer_name: The name of the layer on which to operate
            symbol_table: The name of the table containing the kernel symbols
            filter_string: An optional string which must be present in the hive name if specified 
            offset: An optional offset to specify a specific hive to iterate over (takes precedence over filter_string)

        Yields:
            A registry hive layer name
        """
        if hive_offsets is None:
            try:
                hive_offsets = [
                    hive.vol.offset
                    for hive in hivelist.HiveList.list_hives(context, layer_name, symbol_table, filter_string)
                ]
            except ImportError:
                vollog.warning("Unable to import windows.hivelist plugin, please provide a hive offset")
                raise ValueError("Unable to import windows.hivelist plugin, please provide a hive offset")

        for hive_offset in hive_offsets:
            # Construct the hive
            reg_config_path = cls.make_subconfig(
                context = context,
                base_config_path = base_config_path,
                hive_offset = hive_offset,
                base_layer = layer_name,
                nt_symbols = symbol_table)

            hive = RegistryHive(context, reg_config_path, name = 'hive' + hex(hive_offset))
            context.layers.add_layer(hive)
            yield hive

    def _printkey_iterator(self,
                           hive: RegistryHive,
                           node_path: Sequence[objects.StructType] = None,
                           recurse: bool = False):
        """Method that wraps the more generic key_iterator, to provide output
        for printkey specifically.

        Args:
            hive: The registry hive to walk
            node_path: The list of nodes that make up the
            recurse: Traverse down the node tree or stay only on the same level
        """
        for depth, is_key, last_write_time, key_path, volatile, node in self.key_iterator(hive, node_path, recurse):
            if is_key:
                try:
                    key_node_name = node.get_name()
                except (exceptions.InvalidAddressException, RegistryFormatException) as excp:
                    vollog.debug(excp)
                    key_node_name = renderers.UnreadableValue()

                yield (depth, (last_write_time, renderers.format_hints.Hex(hive.hive_offset), "Key", key_path,
                               key_node_name, "", volatile))
            else:
                try:
                    value_node_name = node.get_name() or "(Default)"
                except (exceptions.InvalidAddressException, RegistryFormatException) as excp:
                    vollog.debug(excp)
                    value_node_name = renderers.UnreadableValue()

                try:
                    value_data = str(node.decode_data())
                except (ValueError, exceptions.InvalidAddressException, RegistryFormatException) as excp:
                    vollog.debug(excp)
                    value_data = renderers.UnreadableValue()

                try:
                    value_type = RegValueTypes.get(node.Type).name
                except (exceptions.InvalidAddressException, RegistryFormatException) as excp:
                    vollog.debug(excp)
                    value_type = renderers.UnreadableValue()

                result = (depth, (last_write_time, renderers.format_hints.Hex(hive.hive_offset), value_type, key_path,
                                  value_node_name, value_data, volatile))
                yield result

    def _registry_walker(self,
                         layer_name: str,
                         symbol_table: str,
                         hive_offsets: List[int] = None,
                         key: str = None,
                         recurse: bool = False):

        for hive in self.hive_iterator(
                self.context,
                self.config_path,
                layer_name = layer_name,
                symbol_table = symbol_table,
                hive_offsets = hive_offsets):

            try:
                # Walk it
                if key is not None:
                    node_path = hive.get_key(key, return_list = True)
                else:
                    node_path = [hive.get_node(hive.root_cell_offset)]
                for (x, y) in self._printkey_iterator(hive, node_path, recurse = recurse):
                    yield (x - len(node_path), y)
            except (exceptions.InvalidAddressException, KeyError, RegistryFormatException) as excp:
                if type(excp) == KeyError:
                    vollog.debug("Key '{}' not found in Hive at offset {}.".format(key, hex(hive.hive_offset)))
                elif type(excp) == RegistryFormatException:
                    vollog.debug(excp)
                else:
                    vollog.debug("Invalid address identified in Hive: {}".format(hex(excp.invalid_address)))
                result = (0, (renderers.UnreadableValue(), format_hints.Hex(hive.hive_offset), "Key",
                              '?\\' + (key or ''), renderers.UnreadableValue(), renderers.UnreadableValue(),
                              renderers.UnreadableValue()))
                yield result

    def run(self):
        offset = self.config.get('offset', None)

        return TreeGrid(
            columns = [('Last Write Time', datetime.datetime), ('Hive Offset', format_hints.Hex), ('Type', str),
                       ('Key', str), ('Name', str), ('Data', str), ('Volatile', bool)],
            generator = self._registry_walker(
                self.config['primary'],
                self.config['nt_symbols'],
                hive_offsets = None if offset is None else [offset],
                key = self.config.get('key', None),
                recurse = self.config.get('recurse', None)))
