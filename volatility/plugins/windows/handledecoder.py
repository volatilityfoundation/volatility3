import volatility.framework.interfaces.plugins as plugins
from volatility.framework.configuration import requirements
from volatility.framework import renderers
from volatility.framework import exceptions
from volatility.framework.renderers import format_hints

try:
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_MODE_32
    has_capsone = True
except ImportError:
    has_capstone = False

class HandleDecoder(plugins.PluginInterface):
    """Find information for decoding handles"""
    
    @classmethod
    def get_requirements(cls):
        return [requirements.TranslationLayerRequirement(name = 'primary',
                                                         description = 'Kernel Address Space'),
                requirements.SymbolRequirement(name = "ntkrnlmp",
                                               description = "Windows OS")]

    def _generator(self):
        for func_addr, sar_value in self.find_sar_value():
            try:
                yield (0, (func_addr, sar_value))
            except exceptions.PagedInvalidAddressException:
                pass

    def find_sar_value(self):
        """Locate ObpCaptureHandleInformationEx if it exists in the 
        sample. Once found, parse it for the SAR value that we need
        to decode pointers in the _HANDLE_TABLE_ENTRY which allows us 
        to find the associated _OBJECT_HEADER."""
        
        if not has_capsone:
            raise StopIteration("Capstone engine is not installed!")
        
        virtual_layer_name = self.config['primary']
        kvo = self.config['primary.kernel_virtual_offset']
        ntkrnlmp = self.context.module("ntkrnlmp", layer_name = virtual_layer_name, offset = kvo)

        try:
            func_addr = ntkrnlmp.get_symbol("ObpCaptureHandleInformationEx").address
        except AttributeError:
            raise StopIteration("Cannot find nt!ObpCaptureHandleInformationEx")
                
        data = self.context.memory.read(virtual_layer_name, kvo + func_addr, 0x200)
        if data == None:
            raise StopIteration("Cannot read data at {:#x}".format(kvo + func_addr))
            
        md = Cs(CS_ARCH_X86, CS_MODE_64)
        
        for (address, size, mnemonic, op_str) in md.disasm_lite(data, kvo + func_addr):
            print("{} {} {} {}".format(address, size, mnemonic, op_str))
                
            if mnemonic.startswith("sar"):
                print("Found: {} {}".format(mnemonic, op_str))
                break
            
        raise StopIteration("OK")

    def run(self):
        return renderers.TreeGrid([("Address", format_hints.Hex),
                         ("SAR", format_hints.Hex)],
                        self._generator())
