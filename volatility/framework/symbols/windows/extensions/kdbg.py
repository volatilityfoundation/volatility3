from volatility.framework import objects
from volatility.framework import constants

class _KDDEBUGGER_DATA64(objects.Struct):

    def get_processes(self):

        layer_name = self.vol.layer_name

        # FIXME: where does this come from?
        nt_symbol_name = "nt_symbols1"

        kvo = self._context.memory[layer_name].config['kernel_virtual_offset']
        ntkrnlmp = self._context.module(nt_symbol_name, layer_name=layer_name, offset=kvo)

        list_pointer = ntkrnlmp.object(type_name="pointer", offset=self.PsActiveProcessHead)
        list_entry = list_pointer.dereference().cast(nt_symbol_name + constants.BANG + "_LIST_ENTRY")

        reloff = ntkrnlmp.get_type("_EPROCESS").relative_child_offset("ActiveProcessLinks")
        eproc = ntkrnlmp.object(type_name="_EPROCESS", offset=list_entry.vol.offset - reloff)

        for proc in eproc.ActiveProcessLinks:
            yield proc

    def get_build_lab(self):
        """Returns the NT build lab string from the KDBG"""

        layer_name = self.vol.layer_name

        # FIXME: where does this come from?
        nt_symbol_name = "nt_symbols1"

        kvo = self._context.memory[layer_name].config['kernel_virtual_offset']
        ntkrnlmp = self._context.module(nt_symbol_name, layer_name=layer_name, offset=kvo)

        return ntkrnlmp.object(type_name="string",
                               offset=self.NtBuildLab,
                               max_length=32,
                               errors="replace")

    def get_csdversion(self):
        """Returns the CSDVersion as an integer (i.e. Service Pack number)"""

        layer_name = self.vol.layer_name
        symbol_table_name = self.get_symbol_table().name

        csdresult = self._context.object(symbol_table_name + constants.BANG + "unsigned long",
                                         layer_name=layer_name,
                                         offset=self.CmNtCSDVersion)

        return (csdresult >> 8) & 0xffffffff