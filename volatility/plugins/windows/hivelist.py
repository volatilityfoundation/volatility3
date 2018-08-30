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
        for hive in self.list_hives(context = self.context,
                                    layer_name = self.config["primary"],
                                    symbol_table = self.config["nt_symbols"],
                                    filter_string = self.config.get('filter', None)):

            yield (0, (format_hints.Hex(hive.vol.offset),
                       hive.get_name() or ""))

    @classmethod
    def list_hives(cls, context, layer_name, symbol_table, filter_string = None):
        """Lists all the hives in the primary layer"""

        # We only use the object factory to demonstrate how to use one
        kvo = context.memory[layer_name].config['kernel_virtual_offset']
        ntkrnlmp = context.module(symbol_table, layer_name = layer_name, offset = kvo)

        list_head = ntkrnlmp.get_symbol("CmpHiveListHead").address
        list_entry = ntkrnlmp.object(type_name = "_LIST_ENTRY", offset = kvo + list_head)
        reloff = ntkrnlmp.get_type("_CMHIVE").relative_child_offset("HiveList")
        cmhive = ntkrnlmp.object(type_name = "_CMHIVE", offset = list_entry.vol.offset - reloff)

        for hive in cmhive.HiveList:
            if filter_string is None or filter_string.lower() in str(hive.get_name() or "").lower():
                yield hive

    def run(self):
        return renderers.TreeGrid([("Offset", format_hints.Hex),
                                   ("FileFullPath", str)],
                                  self._generator())
