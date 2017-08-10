import volatility.framework.interfaces.plugins as plugins
from volatility.framework.configuration import requirements
from volatility.framework import renderers
from volatility.framework import exceptions

class NtObjects(plugins.PluginInterface):
    """Lists the executive object types and their indexes"""
    
    @classmethod
    def get_requirements(cls):
        return [requirements.TranslationLayerRequirement(name = 'primary',
                                                         description = 'Kernel Address Space'),
                requirements.SymbolRequirement(name = "ntkrnlmp",
                                               description = "Windows OS")]

    def _generator(self):
        for i, objt in self.list_objects():
            try:
                yield (0, (i, objt.Name.String))
            except exceptions.PagedInvalidAddressException:
                pass

    def list_objects(self):
        """List the executive object types (_OBJECT_TYPE) using the 
        ObTypeIndexTable or ObpObjectTypes symbol (differs per OS). 
        This method will be necessary for determining what type of 
        object we have given an object header. 
        
        Note: The object type index map was hard coded into profiles 
        in vol2, but we generate it dynamically now."""

        virtual_layer = self.config['primary']
        kvo = self.config['primary.kernel_virtual_offset']
        ntkrnlmp = self.context.module("ntkrnlmp", layer_name = virtual_layer, offset = kvo)

        try:
            table_addr = ntkrnlmp.get_symbol("ObTypeIndexTable").address
        except AttributeError:
            table_addr = ntkrnlmp.get_symbol("ObpObjectTypes").address
                
        ptrs = ntkrnlmp.object(type_name = "array", offset = kvo + table_addr, 
            subtype = self.context.symbol_space.get_type("ntkrnlmp!pointer"), 
            count = 100)

        for i, ptr in enumerate(ptrs):
            # the first entry in the table is always null. break the
            # loop when we encounter the first null entry after that
            if i > 0 and ptr == 0:
                break 
            objt = ptr.dereference().cast("ntkrnlmp!_OBJECT_TYPE")
            yield i, objt 

    def run(self):
        return renderers.TreeGrid([("Index", int),
                         ("ObjectName", str)],
                        self._generator())
