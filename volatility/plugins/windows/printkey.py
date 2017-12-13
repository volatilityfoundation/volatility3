import datetime
import logging

import volatility.framework.interfaces.plugins as plugins
from volatility.framework.configuration import requirements
from volatility.framework.layers.registry import RegistryHive
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

    def update_configuration(self):
        """No operation since all values provided by config/requirements initially"""

    def hive_walker(self, hive, node = None, key_path = None):
        if not node:
            node = hive.get_node(hive.root_cell_offset)
        if key_path is None:
            key_path = node.get_key_path()
        unix_time = node.LastWriteTime.QuadPart // 10000000
        unix_time = unix_time - 11644473600

        for key_node in node.get_subkeys():
            result = (key_path.count("\\"),
                      (str(datetime.datetime.utcfromtimestamp(unix_time)),
                       "Key",
                       key_path,
                       key_node.helper_name,
                       "",
                       key_node.helper_volatile))
            yield result

        for value_node in node.get_values():
            result = (key_path.count("\\"),
                      (str(datetime.datetime.utcfromtimestamp(unix_time)),
                       RegValueTypes(value_node.Type).name,
                       key_path,
                       value_node.helper_name,
                       str(value_node.decode_data()),
                       node.helper_volatile))
            yield result

        if self.config['recurse']:
            for node in node.get_subkeys():
                yield from self.hive_walker(hive, node, key_path + "\\" + node.helper_name)

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
            hive = RegistryHive(self.context, reg_config_path, name = 'hive' + hex(hive_offset), os = 'Windows')
            self.context.memory.add_layer(hive)

            node = None

            # Walk it
            if 'key' in self.config:
                node = hive.get_key(self.config['key'])
            else:
                node = hive.get_node(hive.root_cell_offset)
            yield from self.hive_walker(hive, node)

    def run(self):

        return TreeGrid(columns = [('Last Write Time', str),
                                   ('Type', str),
                                   ('Key', str),
                                   ('Name', str),
                                   ('Data', str),
                                   ('Volatile', bool)],
                        generator = self.registry_walker())
