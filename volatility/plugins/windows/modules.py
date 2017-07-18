import volatility.framework.interfaces.plugins as plugins
from volatility.framework.configuration import requirements
from volatility.framework.renderers import TreeGrid
from volatility.framework.renderers import format_hints
from volatility.framework import exceptions

class Modules(plugins.PluginInterface):
    """Lists the loaded kernel modules"""

    @classmethod
    def get_requirements(cls):
        return [requirements.TranslationLayerRequirement(name = 'primary',
                                                         description = 'Kernel Address Space',
                                                         architectures = ["Intel32", "Intel64"]),
                requirements.SymbolRequirement(name = "ntkrnlmp",
                                               description = "Windows OS")]

    def update_configuration(self):
        """No operation since all values provided by config/requirements initially"""
    
    def _generator(self):
        for mod in self.list_modules():
        
            try:
                BaseDllName = mod.BaseDllName.String
            except exceptions.InvalidAddressException:
                BaseDllName = ""
                
            try:
                FullDllName = mod.FullDllName.String
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

        kvo = self.config['primary.kernel_virtual_offset']
        ntkrnlmp = self.context.module("ntkrnlmp", layer_name = layer_name, offset = kvo)

        list_head = ntkrnlmp.get_symbol("PsLoadedModuleList").address
        list_entry = ntkrnlmp.object(type_name = "_LIST_ENTRY", offset = kvo + list_head)
        reloff = self.context.symbol_space.get_type("ntkrnlmp!_LDR_DATA_TABLE_ENTRY").relative_child_offset("InLoadOrderLinks")
        module = ntkrnlmp.object(type_name = "_LDR_DATA_TABLE_ENTRY", offset = list_entry.vol.offset - reloff)

        for mod in module.InLoadOrderLinks:
            yield mod

    def run(self):
        return TreeGrid([("Offset", format_hints.Hex), 
                         ("Base", format_hints.Hex),
                         ("Size", format_hints.Hex),
                         ("Name", str),
                         ("Path", str)],
                        self._generator())
