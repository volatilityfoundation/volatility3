import time
import volatility.framework.interfaces.plugins as plugins
from volatility.framework.configuration import requirements
from volatility.framework.renderers import TreeGrid
from volatility.framework.symbols.windows.kdbg import KdbgIntermedSymbols
from volatility.framework.symbols.windows.pe import PEIntermedSymbols
from volatility.framework import constants

class Info(plugins.PluginInterface):
    """Show OS & kernel details of the memory sample being analyzed"""

    @classmethod
    def get_requirements(cls):
        return [requirements.TranslationLayerRequirement(name='primary',
                                                         description='Kernel Address Space',
                                                         architectures=["Intel32", "Intel64"]),
                requirements.SymbolRequirement(name="nt_symbols", description="Windows OS")]

    def get_depends(self, layer_name, i=0):
        """List the dependencies of a given layer.

        :param layer_name: the name of the starting layer
        :param i: the index/order of the layer
        """
        layer = self.context.memory[layer_name]
        yield i, layer
        try:
            for depends in layer.dependencies:
                for j, dep in self.get_depends(depends, i + 1):
                    yield j, self.context.memory[dep.name]
        except AttributeError:
            # FileLayer won't have dependencies
            pass

    def _generator(self):

        virtual_layer_name = self.config["primary"]
        virtual_layer = self.context.memory[virtual_layer_name]

        native_types = self.context.symbol_space[self.config["nt_symbols"]].natives

        kdbg_table_name = KdbgIntermedSymbols.create(self.context,
                                                     self.config_path,
                                                     "windows",
                                                     "kdbg",
                                                     native_types = native_types)

        pe_table_name = PEIntermedSymbols.create(self.context,
                                                 self.config_path,
                                                 "windows",
                                                 "pe")

        kvo = virtual_layer.config["kernel_virtual_offset"]

        ntkrnlmp = self.context.module(self.config["nt_symbols"],
                                       layer_name=virtual_layer_name, offset=kvo)

        kdbg_offset = ntkrnlmp.get_symbol("KdDebuggerDataBlock").address

        kdbg = self.context.object(kdbg_table_name + constants.BANG +
                                   "_KDDEBUGGER_DATA64", offset=kvo + kdbg_offset,
                                   layer_name=virtual_layer_name)

        yield (0, ("Memory Location", self.config["primary.memory_layer.location"]))
        yield (0, ("Kernel Base", hex(self.config["primary.kernel_virtual_offset"])))
        yield (0, ("DTB", hex(self.config["primary.page_map_offset"])))
        yield (0, ("Symbols", self.config["nt_symbols.isf_url"]))

        for i, layer in self.get_depends("primary"):
            yield (0, (layer.name, "{} {}".format(i, layer.__class__.__name__)))

        if kdbg.Header.OwnerTag == 0x4742444B:

            yield (0, ("KdDebuggerDataBlock", hex(kdbg.vol.offset)))
            yield (0, ("NTBuildLab", kdbg.get_build_lab()))
            yield (0, ("CSDVersion", str(kdbg.get_csdversion())))

        vers_offset = ntkrnlmp.get_symbol("KdVersionBlock").address

        vers = ntkrnlmp.object(type_name="_DBGKD_GET_VERSION64",
                               layer_name=virtual_layer_name,
                               offset=kvo + vers_offset)

        yield (0, ("KdVersionBlock", hex(vers.vol.offset)))
        yield (0, ("Major/Minor", "{0}.{1}".format(vers.MajorVersion, vers.MinorVersion)))
        yield (0, ("MachineType", str(vers.MachineType)))

        cpu_count_offset = ntkrnlmp.get_symbol("KeNumberProcessors").address

        cpu_count = ntkrnlmp.object(type_name="unsigned int",
                                    layer_name=virtual_layer_name,
                                    offset=kvo + cpu_count_offset)

        yield (0, ("KeNumberProcessors", str(cpu_count)))

        # this is a hard-coded address in the Windows OS
        if virtual_layer.bits_per_register == 32:
            kuser_addr = 0xFFDF0000
        else:
            kuser_addr = 0xFFFFF78000000000

        kuser = ntkrnlmp.object(type_name="_KUSER_SHARED_DATA",
                                layer_name=virtual_layer_name,
                                offset=kuser_addr)

        yield (0, ("SystemTime", str(kuser.SystemTime.get_time())))
        yield (0, ("NtSystemRoot", str(kuser.NtSystemRoot.cast("string",
                                                               encoding="utf-16",
                                                               errors="replace",
                                                               max_length=260))))
        yield (0, ("NtProductType", str(kuser.NtProductType.description)))
        yield (0, ("NtMajorVersion", str(kuser.NtMajorVersion)))
        yield (0, ("NtMinorVersion", str(kuser.NtMinorVersion)))
        #yield (0, ("KdDebuggerEnabled", "True" if ord(kuser.KdDebuggerEnabled) else "False"))
        #yield (0, ("SafeBootMode", "True" if ord(kuser.SafeBootMode) else "False"))

        dos_header = self.context.object(pe_table_name + constants.BANG +
                                   "_IMAGE_DOS_HEADER", offset=kvo,
                                   layer_name=virtual_layer_name)

        nt_header = dos_header.get_nt_header()

        yield (0, ("PE MajorOperatingSystemVersion", str(nt_header.OptionalHeader.MajorOperatingSystemVersion)))
        yield (0, ("PE MinorOperatingSystemVersion", str(nt_header.OptionalHeader.MinorOperatingSystemVersion)))

        yield (0, ("PE Machine", str(nt_header.FileHeader.Machine)))
        yield (0, ("PE TimeDateStamp", time.asctime(time.gmtime(nt_header.FileHeader.TimeDateStamp))))

    def run(self):

        return TreeGrid([("Variable", str),
                         ("Value", str)],
                        self._generator())
