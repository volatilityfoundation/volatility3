# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl_v1.0
#

import datetime
import logging
from typing import Generator, List, Sequence

from volatility.framework import objects, renderers, exceptions, interfaces, constants
from volatility.framework.configuration import requirements
from volatility.framework.layers.registry import RegistryHive, RegistryFormatException
from volatility.framework.renderers import TreeGrid, conversion, format_hints
from volatility.framework.symbols.windows.extensions.registry import RegValueTypes
from volatility.plugins.windows.registry import hivelist

vollog = logging.getLogger(__name__)


class PrintKey(interfaces.plugins.PluginInterface):
    """Lists the registry keys under a hive or specific key value"""

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
    def hive_walker(cls,
                    hive: RegistryHive,
                    node_path: Sequence[objects.StructType] = None,
                    key_path: str = None,
                    recurse: bool = False) -> Generator:
        """Walks through a set of nodes from a given node (last one in node_path).
        Avoids loops by not traversing into nodes already present in the node_path
        """
        if not node_path:
            node_path = [hive.get_node(hive.root_cell_offset)]
        if not isinstance(node_path, list) or len(node_path) < 1:
            vollog.warning("Hive walker was not passed a valid node_path (or None)")
            return
        node = node_path[-1]
        if node.vol.type_name.endswith(constants.BANG + '_CELL_DATA'):
            raise RegistryFormatException("Encountered _CELL_DATA instead of _CM_KEY_NODE")
        key_path = key_path or node.get_key_path()
        last_write_time = conversion.wintime_to_datetime(node.LastWriteTime.QuadPart)

        for key_node in node.get_subkeys():
            try:
                key_node_name = key_node.get_name()
            except (exceptions.InvalidAddressException, RegistryFormatException) as excp:
                vollog.debug(excp)
                key_node_name = renderers.UnreadableValue()

            result = (len(node_path), (last_write_time, renderers.format_hints.Hex(hive.hive_offset), "Key", key_path,
                                       key_node_name, "", key_node.get_volatile()))
            yield result

            if recurse:
                if key_node.vol.offset not in [x.vol.offset for x in node_path]:
                    try:
                        sub_node_name = key_node.get_name()
                    except exceptions.InvalidAddressException as excp:
                        vollog.debug(excp)
                        continue

                    yield from cls.hive_walker(
                        hive, node_path + [key_node], key_path = key_path + "\\" + sub_node_name, recurse = recurse)

        for value_node in node.get_values():
            try:
                value_node_name = value_node.get_name() or "(Default)"
            except (exceptions.InvalidAddressException, RegistryFormatException) as excp:
                vollog.debug(excp)
                value_node_name = renderers.UnreadableValue()

            try:
                value_data = str(value_node.decode_data())
            except (ValueError, exceptions.InvalidAddressException, RegistryFormatException) as excp:
                vollog.debug(excp)
                value_data = renderers.UnreadableValue()

            try:
                value_type = RegValueTypes.get(value_node.Type).name
            except (exceptions.InvalidAddressException, RegistryFormatException) as excp:
                vollog.debug(excp)
                value_type = renderers.UnreadableValue()

            result = (len(node_path), (last_write_time, renderers.format_hints.Hex(hive.hive_offset), value_type,
                                       key_path, value_node_name, value_data, node.get_volatile()))
            yield result

    def registry_walker(self,
                        context: interfaces.context.ContextInterface,
                        layer_name: str,
                        symbol_table: str,
                        offset: int = None,
                        key: str = None):
        """Walks through a registry, hive by hive"""
        if offset is None:
            try:
                hive_offsets = [
                    hive.vol.offset for hive in hivelist.HiveList.list_hives(context, layer_name, symbol_table)
                ]
            except ImportError:
                vollog.warning("Unable to import windows.hivelist plugin, please provide a hive offset")
                raise ValueError("Unable to import windows.hivelist plugin, please provide a hive offset")
        else:
            hive_offsets = [offset]

        for hive_offset in hive_offsets:
            # Construct the hive
            reg_config_path = self.make_subconfig(
                hive_offset = hive_offset, base_layer = layer_name, nt_symbols = symbol_table)
            try:
                hive = RegistryHive(context, reg_config_path, name = 'hive' + hex(hive_offset))
                context.layers.add_layer(hive)

                # Walk it
                if key is not None:
                    node_path = hive.get_key(key, return_list = True)
                else:
                    node_path = [hive.get_node(hive.root_cell_offset)]
                for (x, y) in self.hive_walker(hive, node_path, recurse = self.config.get('recurse', None)):
                    yield (x - len(node_path), y)

            except (exceptions.InvalidAddressException, KeyError, RegistryFormatException) as excp:
                if type(excp) == KeyError:
                    vollog.debug("Key '{}' not found in Hive at offset {}.".format(key, hex(hive_offset)))
                elif type(excp) == RegistryFormatException:
                    vollog.debug(excp)
                else:
                    vollog.debug("Invalid address identified in Hive: {}".format(hex(excp.invalid_address)))
                result = (0, (renderers.UnreadableValue(), format_hints.Hex(hive_offset), "Key", '?\\' + (key or ''),
                              renderers.UnreadableValue(), renderers.UnreadableValue(), renderers.UnreadableValue()))
                yield result

    def run(self):

        return TreeGrid(
            columns = [('Last Write Time', datetime.datetime), ('Hive Offset', format_hints.Hex), ('Type', str),
                       ('Key', str), ('Name', str), ('Data', str), ('Volatile', bool)],
            generator = self.registry_walker(self._context, self.config['primary'], self.config['nt_symbols'],
                                             self.config.get('offset', None), self.config.get('key', None)))
