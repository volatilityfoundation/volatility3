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
