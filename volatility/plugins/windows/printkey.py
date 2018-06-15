import datetime
import logging
import typing

import volatility.framework.interfaces.plugins as plugins
from volatility.framework import objects, renderers, exceptions
from volatility.framework.configuration import requirements
from volatility.framework.layers.registry import RegistryHive
from volatility.framework.objects import utility
from volatility.framework.renderers import TreeGrid
from volatility.framework.symbols.windows.extensions.registry import RegValueTypes

vollog = logging.getLogger(__name__)


class PrintKey(plugins.PluginInterface):
    """Lists the registry keys under a hive or specific key value"""

    @classmethod
    def get_requirements(cls):
        return [requirements.TranslationLayerRequirement(name = 'primary',
                                                         description = 'Kernel Address Space',
                                                         architectures = ["Intel32", "Intel64"]),
                requirements.SymbolRequirement(name = "nt_symbols",
                                               description = "Windows OS"),
                requirements.IntRequirement(name = 'offset',
                                            description = "Hive Offset",
                                            default = None,
                                            optional = True),
                requirements.StringRequirement(name = 'key',
                                               description = "Key to start from",
                                               default = None,
                                               optional = True),
                requirements.BooleanRequirement(name = 'recurse',
                                                description = 'Recurses through keys',
                                                default = False,
                                                optional = True)]

    def hive_walker(self, hive: RegistryHive, node_path: typing.Sequence[objects.Struct] = None, key_path: str = None) \
            -> typing.Generator:
        """Walks through a set of nodes from a given node (last one in node_path).
        Avoids loops by not traversing into nodes already present in the node_path
        """
        if not node_path:
            node_path = [hive.get_node(hive.root_cell_offset)]
        if not isinstance(node_path, list) or len(node_path) < 1:
            vollog.warning("Hive walker was not passed a valid node_path (or None)")
            raise StopIteration
        node = node_path[-1]
        key_path = key_path or node.get_key_path()
        last_write_time = utility.wintime_to_datetime(node.LastWriteTime.QuadPart)

        for key_node in node.get_subkeys():
            result = (key_path.count("\\"),
                      (last_write_time,
                       renderers.format_hints.Hex(hive.hive_offset),
                       "Key",
                       key_path,
                       key_node.get_name(),
                       "",
                       key_node.get_volatile()))
            yield result

        for value_node in node.get_values():
            result = (key_path.count("\\"),
                      (last_write_time,
                       renderers.format_hints.Hex(hive.hive_offset),
                       RegValueTypes(value_node.Type).name,
                       key_path,
                       value_node.get_name(),
                       str(value_node.decode_data()),
                       node.get_volatile()))
            yield result

        if self.config.get('recurse', None):
            for sub_node in node.get_subkeys():
                if sub_node.vol.offset not in [x.vol.offset for x in node_path]:
                    yield from self.hive_walker(hive, node_path + [sub_node], key_path + "\\" + sub_node.get_name())

    def registry_walker(self):
        """Walks through a registry, hive by hive"""
        if self.config.get('offset', None) is None:
            try:
                import volatility.plugins.windows.hivelist as hivelist
                plugin_config_path = self.make_subconfig(primary = self.config['primary'],
                                                         nt_symbols = self.config['nt_symbols'])
                plugin = hivelist.HiveList(self.context, plugin_config_path)
                hive_offsets = [hive.vol.offset for hive in plugin.list_hives()]
            except:
                vollog.warning("Unable to import windows.hivelist plugin, please provide a hive offset")
                raise ValueError("Unable to import windows.hivelist plugin, please provide a hive offset")
        else:
            hive_offsets = [self.config['offset']]

        for hive_offset in hive_offsets:
            # Construct the hive
            reg_config_path = self.make_subconfig(hive_offset = hive_offset,
                                                  base_layer = self.config['primary'],
                                                  nt_symbols = self.config['nt_symbols'])
            try:
                hive = RegistryHive(self.context, reg_config_path, name = 'hive' + hex(hive_offset))
                self.context.memory.add_layer(hive)

                # Walk it
                if 'key' in self.config:
                    node_path = None
                    try:
                        node_path = hive.get_key(self.config['key'], return_list=True)
                    except KeyError:
                        vollog.debug("Key '{}' not found in Hive at offset {}.".format(self.config['key'], hex(hive_offset)))
                        result = (0,
                                  (renderers.UnreadableValue(),
                                   renderers.format_hints.Hex(hive.hive_offset),
                                   "Key",
                                   self.config['key'],
                                   renderers.UnreadableValue(),
                                   renderers.UnreadableValue(),
                                   renderers.UnreadableValue()))
                        yield result
                        continue
                else:
                    node_path = [hive.get_node(hive.root_cell_offset)]
                yield from self.hive_walker(hive, node_path)
            except exceptions.PagedInvalidAddressException as excp:
                vollog.debug("Invalid address identified in Hive: {}".format(hex(excp.invalid_address)))
                result = (0,
                          (renderers.UnreadableValue(),
                           renderers.format_hints.Hex(hive.hive_offset),
                           "Key",
                           self.config['key'],
                           renderers.UnreadableValue(),
                           renderers.UnreadableValue(),
                           renderers.UnreadableValue()))
                yield result

    def run(self):

        return TreeGrid(columns = [('Last Write Time', datetime.datetime),
                                   ('Hive Offset', renderers.format_hints.Hex),
                                   ('Type', str),
                                   ('Key', str),
                                   ('Name', str),
                                   ('Data', str),
                                   ('Volatile', bool)],
                        generator = self.registry_walker())
