from typing import List

from volatility3.framework import interfaces
from volatility3.framework.renderers import TreeGrid, format_hints
from volatility3.framework.interfaces import plugins
from volatility3.framework.configuration import requirements
from volatility3.plugins.windows import modules

GDT_DESCRIPTORS = dict(enumerate([
    "Data RO",
    "Data RO Ac",
    "Data RW",
    "Data RW Ac",
    "Data RO E",
    "Data RO EA",
    "Data RW E",
    "Data RW EA",
    "Code EO",
    "Code EO Ac",
    "Code RE",
    "Code RE Ac",
    "Code EO C",
    "Code EO CA",
    "Code RE C",
    "Code RE CA",
    "<Reserved>",
    "TSS16 Avl",
    "LDT",
    "TSS16 Busy",
    "CallGate16",
    "TaskGate",
    "Int Gate16",
    "TrapGate16",
    "<Reserved>",
    "TSS32 Avl",
    "<Reserved>",
    "TSS32 Busy",
    "CallGate32",
    "<Reserved>",
    "Int Gate32",
    "TrapGate32",
]))

class _KIDT():
    def __init__(self, idt_struct):
        self.idt = idt_struct
        self.Offset = idt_struct.Offset
        self.Selector = idt_struct.Selector
        self.Access = idt_struct.Access
        self.ExtendedOffset = idt_struct.ExtendedOffset

    @property
    def Address(self):
        if self.ExtendedOffset:
            return self.ExtendedOffset << 16 | self.Offset

        return 0
    

class _KGDT():
    def __init__(self, gdt_struct):
        self.gdt = gdt_struct
        self.LimitLow = gdt_struct.LimitLow
        self.BaseLow = gdt_struct.BaseLow
        self.HighWord = gdt_struct.HighWord
    
    @property
    def Type(self):
        """Get a string name of the descriptor type"""
        flag = self.HighWord.Bits.Type & 1 << 4
        typeval = self.HighWord.Bits.Type & ~(1 << 4)

        if flag == 0:
            typeval += 16

        return GDT_DESCRIPTORS.get(typeval, "UNKNOWN")
    
    @property
    def Base(self):
        """Get the base (start) of memory for this GDT"""
        return (self.BaseLow + ((self.HighWord.Bits.BaseMid +
               (self.HighWord.Bits.BaseHi << 8)) << 16))


class _KPCR():
    def __init__(self, kpcr_obj, ntkrnlmp, layer_name, symbol_table):
        self.kpcr = kpcr_obj
        self.ntkrnlmp = ntkrnlmp
        self.layer_name = layer_name
        self.symbol_table = symbol_table
    
    def idt_entries(self):
        base_idt = self.kpcr.IDT
        idt_index = 0
        for idt_index in range(256):
            idt_offset = base_idt + 8 * idt_index
            idt_struct = self.ntkrnlmp.object(
                object_type="_KIDTENTRY",
                layer_name=self.layer_name,
                offset=idt_offset,
                absolute=True
            )
            try:
                yield idt_index, _KIDT(idt_struct)
            except:
                pass

    def gdt_entries(self):
        base_gdt = self.kpcr.GDT

        # Since the real GDT size is read from a register, we'll just assume
        # that there are 128 entries (which is normal for most OS)
        for gdt_index in range(128):
            gdt_offset = base_gdt + 8 * gdt_index
            gdt_struct = self.ntkrnlmp.object(
                object_type="_KGDTENTRY",
                layer_name=self.layer_name,
                offset=gdt_offset,
                absolute=True
            )

            try:
                yield gdt_index, _KGDT(gdt_struct)
            except:
                pass


class IDT(plugins.PluginInterface):
    """Lists the Interrupt Descriptor Table (IDT)"""

    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Windows kernel",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.PluginRequirement(
                name="modules", plugin=modules.Modules, version=(1, 0, 0)
            ),
        ]
    
    def get_module(self, 
        context: interfaces.context.ContextInterface,
        layer_name: str,
        symbol_table: str,
        offset: int):
        try:
            mods = modules.Modules.list_modules(context, layer_name, symbol_table)

            for mod in mods:
                if mod.DllBase + mod.SizeOfImage >= offset and mod.DllBase <= offset:
                    return mod
        except:
            pass
        
        return None
    
    @staticmethod
    def get_section_name(ntkrnlmp, layer_name, mod, addr):
        """Get the name of the PE section containing 
        the specified address. 

        @param ntkrnlmp: ntkrnlmp module object
        @param layer_name: kernel layer name
        @param mod: an _LDR_DATA_TABLE_ENTRY 
        @param addr: virtual address to lookup 
        
        @returns string PE section name
        """
        def name_array_to_str(name_array):
            name = ""
            for char in name_array:
                if char <= 0:
                    break
                name += chr(char)
            return name

        try:
            dos_header = ntkrnlmp.object(
                object_type="_IMAGE_DOS_HEADER",
                layer_name=layer_name,
                offset = mod.DllBase,
                absolute=True)
            nt_header = dos_header.get_nt_header()
        except ValueError:
            return ''

        for sec in nt_header.get_sections():
            if (addr > mod.DllBase + sec.VirtualAddress and
                    addr < sec.Misc.VirtualSize + (mod.DllBase + sec.VirtualAddress)):
                
                return name_array_to_str(sec.Name) or ""

        return ''
    
    def get_pcrs(self, ntkrnlmp, layer_name, symbol_table):
        # Get the number of processors
        cpu_count_offset = ntkrnlmp.get_symbol("KeNumberProcessors").address
        cpu_count = ntkrnlmp.object(
            object_type="unsigned int", layer_name=layer_name, offset=cpu_count_offset
        )

        for cpu_index in range(cpu_count):
            # Calculate the address of KiProcessorBlock
            KiProcessorBlock_addr = ntkrnlmp.get_symbol("KiProcessorBlock").address + cpu_index * 4
            KiProcessorBlock = ntkrnlmp.object(
                object_type="pointer",
                layer_name=layer_name,
                offset=KiProcessorBlock_addr,
            )
            
            # Get kpcr object
            kpcr_offset = ntkrnlmp.get_type("_KPCR").relative_child_offset("PrcbData")
            kpcr = ntkrnlmp.object(
                object_type="_KPCR",
                layer_name=layer_name,
                offset=KiProcessorBlock - kpcr_offset,
                absolute=True)

            yield cpu_index, _KPCR(kpcr, ntkrnlmp, layer_name, symbol_table)

    def _generator(self):
        # Initialize the ntkrnlmp object and etc.
        kernel = self.context.modules[self.config["kernel"]]
        layer_name = kernel.layer_name
        symbol_table = kernel.symbol_table_name
        kvo = self.context.layers[layer_name].config["kernel_virtual_offset"]
        ntkrnlmp = self.context.module(symbol_table, layer_name=layer_name, offset=kvo)

        for cpu_index, kpcr in self.get_pcrs(ntkrnlmp, layer_name, symbol_table):
            gdt = dict((i * 8, sd) for i, sd in kpcr.gdt_entries())
            for idt_index, idt in kpcr.idt_entries():
                addr = idt.Address
                gdt_entry = gdt.get(idt.Selector, None)

                if gdt_entry is not None and "Code" in gdt_entry.Type:
                    addr += gdt_entry.Base

                module = self.get_module(self.context, layer_name, symbol_table, addr)

                if addr == 0:
                    module_name = "NOT USED"
                    sect_name = ''
                elif module:
                    module_name = module.BaseDllName.get_string()
                    sect_name = self.get_section_name(ntkrnlmp, layer_name, module, addr)
                else:
                    module_name = "UNKNOWN"
                    sect_name = ''

                yield (
                    0,
                    (
                        cpu_index,
                        hex(idt_index).replace("0x", "").upper(),
                        format_hints.Hex(idt.Selector),
                        format_hints.Hex(idt.Address),
                        module_name,
                        sect_name
                    )
                )

    def run(self):
        return TreeGrid(
            [
                ('CPU', int),
                ('Index', str),
                ('Selector', format_hints.Hex),
                ('Value', format_hints.Hex),
                ('Module', str),
                ('Section', str)
            ],
            self._generator()
        )