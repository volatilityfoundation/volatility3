import volatility.framework.interfaces.plugins as plugins
import volatility.plugins.windows.pslist as pslist
from volatility.framework import exceptions, renderers
from volatility.framework.configuration import requirements
from volatility.framework.renderers import format_hints

class Handles(plugins.PluginInterface):
    """Lists process open handles"""

    @classmethod
    def get_requirements(cls):
        return [requirements.TranslationLayerRequirement(name = 'primary',
                                                         description = 'Kernel Address Space'),
                requirements.SymbolRequirement(name = "ntkrnlmp",
                                               description = "Windows OS"),
                requirements.IntRequirement(name = 'pid',
                                            description = "Process ID",
                                            optional = True)]

    def get_item(self, handle_table_entry, handle_value):
        virtual = self.config["primary"]
        if not self.context.memory[virtual].is_valid(handle_table_entry.Object):
            return None
        fast_ref = handle_table_entry.Object.cast("ntkrnlmp!_EX_FAST_REF")
        object_header = fast_ref.dereference_as("ntkrnlmp!_OBJECT_HEADER")   
        object_header.HandleValue = handle_value
        object_header.GrantedAccess = handle_table_entry.GrantedAccess
        return object_header
        
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
            
            try:
                type_name = objt.Name.String
            except exceptions.PagedInvalidAddressException:
                continue
            
            yield i, type_name 

    def object_type(self, object_header):
        try:
            # vista and earlier have a Type member 
            return object_header.Type.Name.String
        except AttributeError:
            # windows 7 and later have a TypeIndex, but windows 10
            # further encodes the index value with nt!ObHeaderCookie 
            virtual = self.config["primary"]
            try:
                offset = self.context.symbol_space.get_symbol("nt!ObHeaderCookie").address
                cookie = self.context.object("nt!unsigned int", virtual, offset = offset)
                type_index = ((object_header.vol.offset >> 8) ^ cookie ^ object_header.TypeIndex) & 0xFF    
            except AttributeError:
                type_index = object_header.TypeIndex
            
            type_map = dict((index, type_name) for index, type_name in self.list_objects())
            return type_map[object_header.TypeIndex]

    def make_handle_array(self, offset, level, depth = 0):
    
        if level > 0:
            subtype = self.context.symbol_space.get_type("ntkrnlmp!pointer")
            count = 0x1000 / subtype.size
        else:
            subtype = self.context.symbol_space.get_type("ntkrnlmp!_HANDLE_TABLE_ENTRY")
            count = 0x1000 / subtype.size
           
        kvo = self.config["primary.kernel_virtual_offset"]
        virtual = self.config["primary"]
        ntkrnlmp = self.context.module("ntkrnlmp", layer_name = virtual, offset = kvo) 

        if not self.context.memory[virtual].is_valid(offset):
            raise StopIteration

        table = ntkrnlmp.object(type_name = "array", offset = offset, 
            subtype = subtype, count = int(count))

        for entry in table:

            if level > 0:
                for x in self.make_handle_array(entry, level - 1, depth):
                    yield x
                depth += 1 
            else:
                handle_multiplier = 4
                handle_level_base = depth * count * handle_multiplier
                handle_value = ((entry.vol.offset - offset) /
                               (subtype.size / handle_multiplier)) + handle_level_base

                item = self.get_item(entry, handle_value)

                if item == None:
                    continue 

                try:
                    if item.TypeIndex != 0x0:
                        yield item
                except AttributeError:
                    if item.Type.Name:
                        yield item

    def handles(self, handle_table):
    
        LEVEL_MASK = 7

        try:
            TableCode = handle_table.TableCode & ~LEVEL_MASK
            table_levels = handle_table.TableCode & LEVEL_MASK
        except exceptions.PagedInvalidAddressException:
            raise StopIteration
            
        for handle_table_entry in self.make_handle_array(TableCode, table_levels):
            yield handle_table_entry

    def _generator(self, procs):

        for proc in procs:
        
            try:
                object_table = proc.ObjectTable
            except exceptions.PagedInvalidAddressException:
                continue
        
            process_name = proc.ImageFileName.cast("string", 
                            max_length = proc.ImageFileName.vol.count, 
                            errors = "replace")
            
            for entry in self.handles(object_table):
                try:
                    obj_type = entry.Type.Name.String

                    if obj_type == "File":
                        item = entry.dereference_as("ntkrnlmp!_FILE_OBJECT")
                        obj_name = item.file_name_with_device()
                    elif obj_type == "Process":
                        item = entry.dereference_as("ntkrnlmp!_EPROCESS")
                        obj_name = "{} Pid {}".format(item.ImageFileName.cast("string", 
                                                  max_length = item.ImageFileName.vol.count, 
                                                  errors = "replace"), 
                                                  item.UniqueProcessId)
                    elif obj_type == "Thread":
                        item = entry.dereference_as("ntkrnlmp!_ETHREAD")
                        obj_name = "Tid {} Pid {}".format(item.Cid.UniqueThread, item.Cid.UniqueProcess)
                    elif obj_type == "Key":
                        item = entry.dereference_as("ntkrnlmp!_CM_KEY_BODY")
                        obj_name = item.full_key_name() 
                    else:
                        obj_name = "blah" 
                    
                except exceptions.InvalidAddressException:
                    continue
            
                yield (0, (proc.UniqueProcessId, 
                    process_name, 
                    format_hints.Hex(entry.HandleValue),
                    obj_type, 
                    format_hints.Hex(entry.GrantedAccess),
                    obj_name))

    def run(self):

        plugin = pslist.PsList(self.context, "plugins.Handles")

        return renderers.TreeGrid([("PID", int),
                                   ("Process", str),
                                   ("HandleValue", format_hints.Hex),
                                   ("Type", str),
                                   ("GrantedAccess", format_hints.Hex),
                                   ("Name", str)],
                                  self._generator(plugin.list_processes()))
