import datetime

import volatility.framework.interfaces.plugins as plugins
from volatility.framework.configuration import requirements
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
                yield from self.registry_walker(registry, node)

    def run(self):
        reg_config_path = self.make_subconfig(hive_offset = self.config['offset'],
                                              base_layer = self.config['primary'],
                                              ntsymbols = self.config['ntsymbols'])
        registry_layer = RegistryHive(self.context, reg_config_path, name = 'hive', os = 'Windows')
        self.context.memory.add_layer(registry_layer)

        node = None
        if self.config.get('key', None):
            node = registry_layer.get_key(self.config['key'])

        return TreeGrid(columns = [('Last Write Time', str),
                                   ('Type', str),
                                   ('Key', str),
                                   ('Name', str),
                                   ('Data', str),
                                   ('Volatile', bool)],
                        generator = self.registry_walker(registry_layer, node = node))
