from volatility.framework import objects

class _KDDEBUGGER_DATA64(objects.Struct):

    def get_processes(self):

        layer_name = self.vol.layer_name
        symbol_table_name = self.get_symbol_table().name

        kvo = self._context.memory[layer_name].config["kernel_virtual_offset"]
        ntkrnlmp = self._context.module(symbol_table_name, layer_name=layer_name, offset=kvo)

        ## help please!
        list_pointer = ntkrnlmp.object(type_name="nt_symbols!pointer", offset=self.PsActiveProcessHead)
        yield list_pointer
