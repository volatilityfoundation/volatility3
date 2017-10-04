import volatility.framework.interfaces.plugins as plugins
from volatility.framework import renderers
from volatility.framework.configuration import requirements
from volatility.framework.renderers import format_hints


class HiveList(plugins.PluginInterface):
    """Lists the registry hives present in a particular memory image"""

    @classmethod
    def get_requirements(cls):
        return [requirements.TranslationLayerRequirement(name = 'primary',
                                                         description = 'Kernel Address Space',
                                                         architectures = ["Intel32", "Intel64"]),
                requirements.SymbolRequirement(name = "nt", description = "Windows OS")]

    def update_configuration(self):
        """No operation since all values provided by config/requirements initially"""

    def _generator(self):
        for hive in self.list_hives():

            yield (0, (format_hints.Hex(hive.vol.offset),
                       hive.name or ""))

    def list_hives(self):
        """Lists all the hives in the primary layer"""

        layer_name = self.config['primary']

        # We only use the object factory to demonstrate how to use one
        kvo = self.config['primary.kernel_virtual_offset']
        ntkrnlmp = self.context.module(self.config["nt"], layer_name = layer_name, offset = kvo)

        list_head = ntkrnlmp.get_symbol("CmpHiveListHead").address
        list_entry = ntkrnlmp.object(type_name = "_LIST_ENTRY", offset = kvo + list_head)
        reloff = ntkrnlmp.get_type("_CMHIVE").relative_child_offset("HiveList")
        cmhive = ntkrnlmp.object(type_name = "_CMHIVE", offset = list_entry.vol.offset - reloff)

        for hive in cmhive.HiveList:
            yield hive

    def run(self):
        return renderers.TreeGrid([("Offset", format_hints.Hex),
                                   ("FileFullPath", str)],
                                  self._generator())
