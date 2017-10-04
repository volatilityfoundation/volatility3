import volatility.framework.interfaces.plugins as interfaces_plugins
import volatility.plugins.windows.pslist as pslist
from volatility.framework import exceptions, renderers
from volatility.framework.configuration import requirements
from volatility.framework.renderers import format_hints
from volatility.framework import constants
from volatility.framework.objects import utility

class Handles(interfaces_plugins.PluginInterface):
    """Lists process open handles"""

    @classmethod
    def get_requirements(cls):
        # Since we're calling the plugin, make sure we have the plugin's requirements
        return pslist.PsList.get_requirements() + []

    def decode_pointer(self, value, magic):
                    
        value = value & 0xFFFFFFFFFFFFFFF8
        value = value >> magic
        if (value & (1 << 47)):
            value = value | 0xFFFF000000000000
    
        return value

    def get_item(self, handle_table_entry, handle_value):
        virtual = self.config["primary"]
        
        try:
            # before windows 7 
            if not self.context.memory[virtual].is_valid(handle_table_entry.Object):
                return None
            fast_ref = handle_table_entry.Object.cast(self.config["nt"] + constants.BANG + "_EX_FAST_REF")
            object_header = fast_ref.dereference_as(self.config["nt"] + constants.BANG + "_OBJECT_HEADER")  
            object_header.GrantedAccess = handle_table_entry.GrantedAccess
        except AttributeError:
            # starting with windows 8 
            if handle_table_entry.LowValue == 0:
                return None
                
            magic = 0x10 
            offset = self.decode_pointer(handle_table_entry.LowValue, magic)
            object_header = self.context.object(self.config["nt"] + constants.BANG + "_OBJECT_HEADER", virtual, offset = offset)
            object_header.GrantedAccess = handle_table_entry.GrantedAccessBits
         
        object_header.HandleValue = handle_value
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
        ntkrnlmp = self.context.module(self.config["nt"], layer_name = virtual_layer, offset = kvo)

        try:
            table_addr = ntkrnlmp.get_symbol("ObTypeIndexTable").address
        except AttributeError:
            table_addr = ntkrnlmp.get_symbol("ObpObjectTypes").address
                
        ptrs = ntkrnlmp.object(type_name = "array", offset = kvo + table_addr, 
            subtype = ntkrnlmp.get_type("pointer"), 
            count = 100)

        for i, ptr in enumerate(ptrs):
            # the first entry in the table is always null. break the
            # loop when we encounter the first null entry after that
            if i > 0 and ptr == 0:
                break 
            objt = ptr.dereference().cast(self.config["nt"] + constants.BANG + "_OBJECT_TYPE")
            
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
            # further encodes the index value with nt1!ObHeaderCookie 
            virtual = self.config["primary"]
            try:
                offset = self.context.symbol_space.get_symbol(self.config["nt"] + constants.BANG + "ObHeaderCookie").address
                kvo = self.config['primary.kernel_virtual_offset']
                cookie = self.context.object(self.config["nt"] + constants.BANG + "unsigned int", virtual, offset = kvo + offset)
                type_index = ((object_header.vol.offset >> 8) ^ cookie ^ ord(object_header.TypeIndex)) & 0xFF    
            except AttributeError:
                type_index = ord(object_header.TypeIndex)
            
            type_map = dict((index, type_name) for index, type_name in self.list_objects())
            return type_map.get(type_index)

    def make_handle_array(self, offset, level, depth = 0):
    
        kvo = self.config["primary.kernel_virtual_offset"]
        virtual = self.config["primary"]
        ntkrnlmp = self.context.module(self.config["nt"], layer_name = virtual, offset = kvo) 
    
        if level > 0:
            subtype = ntkrnlmp.get_type("pointer")
            count = 0x1000 / subtype.size
        else:
            subtype = ntkrnlmp.get_type("_HANDLE_TABLE_ENTRY")
            count = 0x1000 / subtype.size

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
                except exceptions.PagedInvalidAddressException:
                    continue

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
        
            process_name = utility.array_to_string(proc.ImageFileName)
            
            for entry in self.handles(object_table):
                #try:
                obj_type = self.object_type(entry)
                
                if obj_type == None:
                    continue
                
                if obj_type == "File":
                    item = entry.dereference_as(self.config["nt"] + constants.BANG + "_FILE_OBJECT")
                    obj_name = item.file_name_with_device()
                elif obj_type == "Process":
                    item = entry.dereference_as(self.config["nt"] + constants.BANG + "_EPROCESS")
                    obj_name = "{} Pid {}".format(utility.array_to_string(proc.ImageFileName),
                                              item.UniqueProcessId)
                elif obj_type == "Thread":
                    item = entry.dereference_as(self.config["nt"] + constants.BANG + "_ETHREAD")
                    obj_name = "Tid {} Pid {}".format(item.Cid.UniqueThread, item.Cid.UniqueProcess)
                elif obj_type == "Key":
                    item = entry.dereference_as(self.config["nt"] + constants.BANG + "_CM_KEY_BODY")
                    obj_name = item.full_key_name() 
                else:
                    obj_name = "blah" 
                    
            #except exceptions.InvalidAddressException:
            #continue
            
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
