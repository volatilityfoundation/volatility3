import volatility.framework.interfaces.plugins as plugins
from volatility.framework import exceptions
from volatility.framework import renderers
from volatility.framework.configuration import requirements
from volatility.framework.renderers import format_hints


class Modules(plugins.PluginInterface):
    """Lists the loaded kernel modules"""

    @classmethod
    def get_requirements(cls):
        return [requirements.TranslationLayerRequirement(name = 'primary',
                                                         description = 'Kernel Address Space',
                                                         architectures = ["Intel32", "Intel64"]),
                requirements.SymbolRequirement(name = "nt", description = "Windows OS")]

    def update_configuration(self):
        """No operation since all values provided by config/requirements initially"""

    def _generator(self):
        for mod in self.list_modules():

            try:
                BaseDllName = mod.BaseDllName.helper_string
            except exceptions.InvalidAddressException:
                BaseDllName = ""

            try:
                FullDllName = mod.FullDllName.helper_string
            except exceptions.InvalidAddressException:
                FullDllName = ""

            yield (0, (format_hints.Hex(mod.vol.offset),
                       format_hints.Hex(mod.DllBase),
                       format_hints.Hex(mod.SizeOfImage),
                       BaseDllName,
                       FullDllName,
                       ))

    def list_modules(self):
        """Lists all the modules in the primary layer"""

        layer_name = self.config['primary']

        kvo = self.context.memory[layer_name].config['kernel_virtual_offset']
        ntkrnlmp = self.context.module(self.config["nt"], layer_name = layer_name, offset = kvo)

        list_head = ntkrnlmp.get_symbol("PsLoadedModuleList").address
        list_entry = ntkrnlmp.object(type_name = "_LIST_ENTRY", offset = kvo + list_head)
        reloff = ntkrnlmp.get_type("_LDR_DATA_TABLE_ENTRY").relative_child_offset("InLoadOrderLinks")
        module = ntkrnlmp.object(type_name = "_LDR_DATA_TABLE_ENTRY", offset = list_entry.vol.offset - reloff)

        for mod in module.InLoadOrderLinks:
            yield mod

    def run(self):
        return renderers.TreeGrid([("Offset", format_hints.Hex),
                                   ("Base", format_hints.Hex),
                                   ("Size", format_hints.Hex),
                                   ("Name", str),
                                   ("Path", str)],
                                  self._generator())
