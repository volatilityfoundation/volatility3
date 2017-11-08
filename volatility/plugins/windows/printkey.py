import datetime

import volatility.framework.interfaces.plugins as plugins
from volatility.framework.configuration import requirements
from volatility.framework.interfaces import configuration
from volatility.framework.interfaces.configuration import HierarchicalDict
from volatility.framework.layers.registry import RegistryHive
from volatility.framework.renderers import TreeGrid
from volatility.framework.symbols.windows.extensions.registry import RegValueTypes


class PrintKey(plugins.PluginInterface):
    """Lists the processes present in a particular memory image"""

    @classmethod
    def get_requirements(cls):
        return [requirements.TranslationLayerRequirement(name = 'primary',
                                                         description = 'Kernel Address Space',
                                                         architectures = ["Intel32", "Intel64"]),
                requirements.SymbolRequirement(name = "ntsymbols",
                                               description = "Windows OS"),
                requirements.IntRequirement(name = 'offset',
                                            description = "Hive Offset",
                                            default = 0),
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

    def registry_walker(self, registry, node = None):
        if not node:
            node = registry.get_node(registry.root_cell_offset)
        key_path = node.get_key_path()
        unix_time = node.LastWriteTime.QuadPart // 10000000
        unix_time = unix_time - 11644473600

        for key_node in node.get_subkeys():
            result = (key_path.count("\\"),
                      (key_path,
                       str(datetime.datetime.utcfromtimestamp(unix_time)),
                       "Key",
                       key_node.helper_name,
                       "",
                       key_node.volatile))
            yield result

        for value_node in node.get_values():
            result = (key_path.count("\\"),
                      (key_path,
                       str(datetime.datetime.utcfromtimestamp(unix_time)),
                       RegValueTypes(value_node.Type).name,
                       value_node.helper_name,
                       str(value_node.decode_data()),
                       node.volatile))
            yield result

        if self.config['recurse']:
            for node in node.get_subkeys():
                yield from self.registry_walker(registry, node)

    def run(self):
        layer = self.context.memory[self.config['primary']]
        reg_config = HierarchicalDict({'hive_offset': self.config['offset'],
                                       'base_layer': self.config['primary'],
                                       'ntsymbols': self.config['ntsymbols']})
        self.config.splice('registry', reg_config)

        registry_config_path = configuration.path_join(self.config_path, 'registry')
        registry_layer = RegistryHive(self.context, registry_config_path, name = 'hive', os = 'Windows')
        self.context.memory.add_layer(registry_layer)

        node = None
        if self.config.get('key', None):
            node = registry_layer.get_key(self.config['key'])

        return TreeGrid(columns = [('Key', str),
                                   ('Last Write Time', str),
                                   ('Type', str),
                                   ('Name', str),
                                   ('Data', str),
                                   ('Volatile', bool)],
                        generator = self.registry_walker(registry_layer, node = node))
