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
                requirements.SymbolRequirement(name = "nt_symbols", description = "Windows OS"),
                requirements.StringRequirement(name = 'filter',
                                               description = "String to filter hive names returned",
                                               optional = True,
                                               default = None)]

    def _generator(self):
        for hive in self.list_hives():

            yield (0, (format_hints.Hex(hive.vol.offset),
                       hive.get_name() or ""))

    def list_hives(self):
        """Lists all the hives in the primary layer"""

        layer_name = self.config['primary']

        # We only use the object factory to demonstrate how to use one
        kvo = self.context.memory[layer_name].config['kernel_virtual_offset']
        ntkrnlmp = self.context.module(self.config["nt_symbols"], layer_name = layer_name, offset = kvo)

        list_head = ntkrnlmp.get_symbol("CmpHiveListHead").address
        list_entry = ntkrnlmp.object(type_name = "_LIST_ENTRY", offset = kvo + list_head)
        reloff = ntkrnlmp.get_type("_CMHIVE").relative_child_offset("HiveList")
        cmhive = ntkrnlmp.object(type_name = "_CMHIVE", offset = list_entry.vol.offset - reloff)

        for hive in cmhive.HiveList:
            if self.config.get("filter", None) is None or self.config["filter"].lower() in str(hive.get_name() or "").lower():
                yield hive

    def run(self):
        return renderers.TreeGrid([("Offset", format_hints.Hex),
                                   ("FileFullPath", str)],
                                  self._generator())
