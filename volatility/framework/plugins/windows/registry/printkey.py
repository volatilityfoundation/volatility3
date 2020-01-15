# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

import datetime
import logging
from typing import List, Sequence, Iterable, Tuple, Union

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
            requirements.TranslationLayerRequirement(name = 'primary',
                                                     description = 'Memory layer for the kernel',
                                                     architectures = ["Intel32", "Intel64"]),
            requirements.SymbolTableRequirement(name = "nt_symbols", description = "Windows kernel symbols"),
            requirements.PluginRequirement(name = 'hivelist', plugin = hivelist.HiveList, version = (1, 0, 0)),
            requirements.IntRequirement(name = 'offset', description = "Hive Offset", default = None, optional = True),
            requirements.StringRequirement(name = 'key',
                                           description = "Key to start from",
                                           default = None,
                                           optional = True),
            requirements.BooleanRequirement(name = 'recurse',
                                            description = 'Recurses through keys',
                                            default = False,
                                            optional = True)
        ]

    @classmethod
    def key_iterator(cls, hive: RegistryHive, node_path: Sequence[objects.StructType] = None, recurse: bool = False
                     ) -> Iterable[Tuple[int, bool, datetime.datetime, str, bool, interfaces.objects.ObjectInterface]]:
        """Walks through a set of nodes from a given node (last one in
        node_path). Avoids loops by not traversing into nodes already present
        in the node_path.

        Args:
            hive: The registry hive to walk
            node_path: The list of nodes that make up the
            recurse: Traverse down the node tree or stay only on the same level

        Yields:
            A tuple of results (depth, is_key, last write time, path, volatile, and the node).
        """
        if not node_path:
            node_path = [hive.get_node(hive.root_cell_offset)]
        if not isinstance(node_path, list) or len(node_path) < 1:
            vollog.warning("Hive walker was not passed a valid node_path (or None)")
            return
        node = node_path[-1]
        key_path = '\\'.join([k.get_name() for k in node_path])
        if node.vol.type_name.endswith(constants.BANG + '_CELL_DATA'):
            raise RegistryFormatException(hive.name, "Encountered _CELL_DATA instead of _CM_KEY_NODE")
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

        Yields:
            The depth, and a tuple of results (last write time, hive offset, type, path, name, data and volatile)
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
                    value_data = str(node.decode_data())  # type: Union[interfaces.renderers.BaseAbsentValue, str]
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

        for hive in hivelist.HiveList.list_hives(self.context,
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
                if isinstance(excp, KeyError):
                    vollog.debug("Key '{}' not found in Hive at offset {}.".format(key, hex(hive.hive_offset)))
                elif isinstance(excp, RegistryFormatException):
                    vollog.debug(excp)
                elif isinstance(excp, exceptions.InvalidAddressException):
                    vollog.debug("Invalid address identified in Hive: {}".format(hex(excp.invalid_address)))
                result = (0, (renderers.UnreadableValue(), format_hints.Hex(hive.hive_offset), "Key",
                              '?\\' + (key or ''), renderers.UnreadableValue(), renderers.UnreadableValue(),
                              renderers.UnreadableValue()))
                yield result

    def run(self):
        offset = self.config.get('offset', None)

        return TreeGrid(columns = [('Last Write Time', datetime.datetime), ('Hive Offset', format_hints.Hex),
                                   ('Type', str), ('Key', str), ('Name', str), ('Data', str), ('Volatile', bool)],
                        generator = self._registry_walker(self.config['primary'],
                                                          self.config['nt_symbols'],
                                                          hive_offsets = None if offset is None else [offset],
                                                          key = self.config.get('key', None),
                                                          recurse = self.config.get('recurse', None)))
