import volatility.framework.interfaces.plugins as plugins
from volatility.framework.configuration import requirements
from volatility.framework.interfaces import configuration
from volatility.framework.interfaces.configuration import HierarchicalDict
from volatility.framework.layers.registry import RegistryHive


class RegTest(plugins.PluginInterface):
    """Lists the processes present in a particular memory image"""

    @classmethod
    def get_requirements(cls):
        return [requirements.TranslationLayerRequirement(name = 'primary',
                                                         description = 'Kernel Address Space',
                                                         architectures = ["Intel32", "Intel64"]),
                requirements.SymbolRequirement(name = "ntkrnlmp",
                                               description = "Windows OS"),
                requirements.IntRequirement(name = 'offset',
                                            description = "Hive Offset",
                                            default = 0,
                                            optional = True)]

    def update_configuration(self):
        """No operation since all values provided by config/requirements initially"""

    def run(self):
        layer = self.context.memory[self.config['primary']]
        reg_config = HierarchicalDict({'hive_offset': 0xe1ca8210,
                                       'base_layer': self.config['primary'],
                                       'ntkrnlmp': self.config['ntkrnlmp']})
        self.config.splice('registry', reg_config)

        registry_config_path = configuration.path_join(self.config_path, 'registry')
        registry_layer = RegistryHive(self.context, registry_config_path, name = 'hive0', os = 'Windows')
        self.context.memory.add_layer(registry_layer)
