import volatility.framework.interfaces.plugins as plugins
from volatility.framework.configuration import requirements
from volatility.framework.renderers import TreeGrid
from volatility.framework.symbols import intermed
from volatility.framework import constants

class WinInfo(plugins.PluginInterface):
    @classmethod
    def get_requirements(cls):
        return [requirements.TranslationLayerRequirement(name='primary',
                                                         description='Kernel Address Space',
                                                         architectures=["Intel32", "Intel64"]),
                requirements.SymbolRequirement(name="nt_symbols", description="Windows OS")]

    def _generator(self, kdbg):
        yield (0, ("Foo", "Bar"))

    def run(self):
        virtual_layer_name = self.config["primary"]
        virtual_layer = self.context.memory[virtual_layer_name]

        kdbg_table_name = intermed.IntermediateSymbolTable.create(self.context,
                                                                   self.config_path,
                                                                   "windows",
                                                                   "kdbg_{}".format(virtual_layer.bits_per_register))

        kvo = virtual_layer.config["kernel_virtual_offset"]
        ntkrnlmp = self.context.module(self.config["nt_symbols"], layer_name=virtual_layer_name, offset=kvo)

        kdbg_offset = ntkrnlmp.get_symbol("KdDebuggerDataBlock").address

        kdbg = self.context.object(kdbg_table_name + constants.BANG +
                            "_KDDEBUGGER_DATA64", offset=kvo + kdbg_offset,
                            layer_name=virtual_layer_name)

        #vers_addr = kvo + self.context.symbol_space.get_symbol("ntkrnlmp!KdVersionBlock").address
        #vers = self.context.object("ntkrnlmp!_DBGKD_GET_VERSION64", layer_name=virtual, offset=vers_addr)

        return TreeGrid([("Variable", str),
                         ("Value", str)],
                        self._generator(kdbg))