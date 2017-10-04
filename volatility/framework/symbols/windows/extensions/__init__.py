import collections.abc

from volatility.framework import constants, exceptions, objects
from volatility.framework.symbols import generic


# Keep these in a basic module, to prevent import cycles when symbol providers require them

class _EX_FAST_REF(objects.Struct):
    def dereference_as(self, target):
    
        # the mask value is different on 32 and 64 bits 
        if self._context.symbol_space.get_type("nt1!pointer").size == 4:
            max_fast_ref = 7
        else:
            max_fast_ref = 15
    
        return self._context.object(target, layer_name = self.vol.layer_name, offset = self.Object & ~max_fast_ref)

class ExecutiveObject(object):
    def object_header(self):
        body_offset = self._context.symbol_space.get_type("nt1!_OBJECT_HEADER").relative_child_offset("Body") 
        return self._context.object("nt1!_OBJECT_HEADER", layer_name = self.vol.layer_name, offset = self.vol.offset - body_offset)

class _CM_KEY_BODY(objects.Struct):
    def full_key_name(self):
        output = []
        kcb = self.KeyControlBlock
        while kcb.ParentKcb:
            if kcb.NameBlock.Name == None:
                break
            output.append(kcb.NameBlock.Name.cast("string", 
                          encoding = "utf8", 
                          max_length = kcb.NameBlock.NameLength, 
                          errors = "replace"))
            kcb = kcb.ParentKcb
        return "\\".join(reversed(output))

class _DEVICE_OBJECT(objects.Struct, ExecutiveObject):
    def device_name(self):
        header = self.object_header()
        return header.NameInfo.Name.String

class _FILE_OBJECT(objects.Struct, ExecutiveObject):
    def file_name_with_device(self):
        name = ""
        if self._context.memory[self.vol.layer_name].is_valid(self.DeviceObject):
            name = "\\Device\\{}".format(self.DeviceObject.device_name())
        name += self.FileName.String
        return name

class _OBJECT_HEADER(objects.Struct):
    def dereference_as(self, target):
        return self._context.object(target, layer_name = self.vol.layer_name, offset = self.Body.vol.offset)

    @property
    def NameInfo(self):
        try:
            header_offset = ord(self.NameInfoOffset)
        except AttributeError:
            #http://codemachine.com/article_objectheader.html
            name_info_bit = 0x2 
            
            layer = self._context.memory[self.vol.layer_name]            
            kvo = layer.config["kernel_virtual_offset"]
                    
            # is this the right thing to raise here?
            if kvo == None:
                raise AttributeError
            
            ntkrnlmp = self._context.module(layer.config["nt"], layer_name = self.vol.layer_name, offset = kvo)
            address = ntkrnlmp.get_symbol("ObpInfoMaskToOffset").address
            calculated_index = ord(self.InfoMask) & (name_info_bit | (name_info_bit - 1))
                        
            header_offset = self._context.object(layer.config["nt"] + constants.BANG + "unsigned char", 
                                                layer_name = self.vol.layer_name, 
                                                offset = kvo + address + calculated_index)
                                                
            header_offset = ord(header_offset)
                                                                                                   
        header = self._context.object(layer.config["nt"] + constants.BANG + "_OBJECT_HEADER_NAME_INFO", 
                                      layer_name = self.vol.layer_name, 
                                      offset = self.vol.offset - header_offset)
        return header

class _HANDLE_TABLE_ENTRY(objects.Struct):
    def object_header(self):
        
        if self.context.symbol_space.get_type("nt1!pointer").size == 4:
            # xp/2003/vista use Object. windows 8 and above uses LowValue 
            # both are placeholders for _EX_FAST_REF instances 
            try:
                ex_fast_ref = self.Object.cast("_EX_FAST_REF")
            except AttributeError:
                ex_fast_ref = self.LowValue.cast("_EX_FAST_REF")
                
            return ex_fast_ref.dereference_as("_OBJECT_HEADER")
        else:
            # xp/2003/vista use Object. windows 8 and above uses LowValue 
            # however LowValue is encoded differently per version 
            try:
                ex_fast_ref = self.Object.cast("_EX_FAST_REF")
                return ex_fast_ref.dereference_as("_OBJECT_HEADER")
            except AttributeError:
                # where do we get sar from?
                header_ptr = self.decode_pointer(sar)
                return self._context.object("nt1!_OBJECT_HEADER", self.vol.layer_name, offset = header_ptr)
                
    def decode_pointer(self, sar):
        value = self.LowValue & 0xFFFFFFFFFFFFFFF8 >> sar 
        if value & 1 << 44:
            return value | 0xFFFFF00000000000
        else:
            return value | 0xFFFF000000000000

class _ETHREAD(objects.Struct):
    def owning_process(self, kernel_layer = None):
        """Return the EPROCESS that owns this thread"""
        return self.ThreadsProcess.dereference(kernel_layer)


class _CMHIVE(objects.Struct):
    @property
    def name(self):
        """Determine a name for the hive. Note that some attributes are
        unpredictably blank across different OS versions while others are populated,
        so we check all possibilities and take the first one that's not empty"""

        for attr in ["FileFullPath", "FileUserName", "HiveRootPath"]:
            try:
                return getattr(self, attr).String
            except (AttributeError, exceptions.InvalidAddressException):
                pass

        return None


class _UNICODE_STRING(objects.Struct):
    @property
    def String(self):
        # We explicitly do *not* catch errors here, we allow an exception to be thrown
        # (otherwise there's no way to determine anything went wrong)
        # It's up to the user of this method to catch exceptions
        return self.Buffer.dereference().cast("string", max_length = self.Length, errors = "replace",
                                              encoding = "utf16")


class _EPROCESS(generic.GenericIntelProcess):
    def add_process_layer(self, context, config_prefix = None, preferred_name = None):
        """Constructs a new layer based on the process's DirectoryTableBase"""

        parent_layer = context.memory[self.vol.layer_name]
        # Presumably for 64-bit systems, the DTB is defined as an array, rather than an unsigned long long
        if isinstance(self.Pcb.DirectoryTableBase, objects.Array):
            dtb = self.Pcb.DirectoryTableBase.cast("unsigned long long")
        else:
            dtb = self.Pcb.DirectoryTableBase
        dtb = dtb & ((1 << parent_layer.bits_per_register) - 1)

        # Add the constructed layer and return the name
        return self._add_process_layer(context, dtb, config_prefix, preferred_name)

    def load_order_modules(self):
        """Generator for DLLs in the order that they were loaded"""

        proc_layer_name = self.add_process_layer(self._context)

        proc_layer = self._context.memory[proc_layer_name]
        if not proc_layer.is_valid(self.Peb):
            raise StopIteration

        sym_table = self.vol.type_name.split(constants.BANG)[0]
        peb = self._context.object("{}{}_PEB".format(sym_table, constants.BANG), layer_name = proc_layer_name,
                                   offset = self.Peb)

        for entry in peb.Ldr.InLoadOrderModuleList.to_list(
                "{}{}_LDR_DATA_TABLE_ENTRY".format(sym_table, constants.BANG), "InLoadOrderLinks"):
            yield entry


class _LIST_ENTRY(objects.Struct, collections.abc.Iterable):
    def to_list(self, symbol_type, member, forward = True, sentinel = True, layer = None):
        """Returns an iterator of the entries in the list"""

        if layer is None:
            layer = self.vol.layer_name

        relative_offset = self._context.symbol_space.get_type(symbol_type).relative_child_offset(member)

        direction = 'Blink'
        if forward:
            direction = 'Flink'
        link = getattr(self, direction).dereference()

        if not sentinel:
            yield self._context.object(symbol_type, layer, offset = self.vol.offset - relative_offset)

        seen = {self.vol.offset}
        while link.vol.offset not in seen:

            obj = self._context.object(symbol_type, layer, offset = link.vol.offset - relative_offset)
            yield obj

            seen.add(link.vol.offset)
            link = getattr(link, direction).dereference()

    def __iter__(self):
        return self.to_list(self.vol.parent.vol.type_name, self.vol.member_name)
