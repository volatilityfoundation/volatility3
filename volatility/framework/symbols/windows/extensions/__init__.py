import collections.abc
import functools
import logging
import typing

import volatility.framework.objects.utility
from volatility.framework import constants, exceptions, interfaces, objects, renderers, symbols
from volatility.framework.layers import intel
from volatility.framework.symbols import generic
from volatility.framework.symbols.windows.extensions.registry import RegKeyFlags

vollog = logging.getLogger(__name__)


# Keep these in a basic module, to prevent import cycles when symbol providers require them

class _POOL_HEADER(objects.Struct):
    """A kernel pool allocation header. Exists at the base of the
    allocation and provides a tag that we can scan for."""

    def get_object(self,
                   type_name: str,
                   native_layer_name: str = None,
                   object_type: str = None) -> typing.Optional[interfaces.objects.ObjectInterface]:
        """Carve an object or data structure from a kernel pool allocation.

        :param type_name: the data structure type name
        :param native_layer_name: the name of the layer where the data originally lived
        :param object_type: the object type (executive kernel objects only)
        :return:
        """

        symbol_table_name = self.vol.type_name.split(constants.BANG)[0]
        pool_header_size = self._context.symbol_space.get_type(symbol_table_name + constants.BANG + "_POOL_HEADER").size

        # if there is no object type, then just instantiate a structure
        if object_type is None:
            mem_object = self._context.object(symbol_table_name + constants.BANG + type_name,
                                              layer_name = self.vol.layer_name,
                                              offset = self.vol.offset + pool_header_size,
                                              native_layer_name = native_layer_name)
            return mem_object

        # otherwise we have an executive object in the pool
        else:
            alignment = pool_header_size
            type_size = self._context.symbol_space.get_type(symbol_table_name + constants.BANG + type_name).size
            rounded_size = objects.utility.round(type_size, alignment, up = True)

            mem_object = self._context.object(symbol_table_name + constants.BANG + type_name,
                                              layer_name = self.vol.layer_name,
                                              offset = self.vol.offset + self.BlockSize * alignment - rounded_size,
                                              native_layer_name = native_layer_name)

            object_header = mem_object.object_header()

            try:
                object_type_string = object_header.NameInfo.Name.String
                if object_type_string == object_type:
                    return mem_object
                else:
                    return None
            except (TypeError, exceptions.InvalidAddressException):
                return None


class _KSYSTEM_TIME(objects.Struct):
    """A system time structure that stores a high and low part."""

    def get_time(self):
        wintime = (self.High1Time << 32) | self.LowPart
        return objects.utility.wintime_to_datetime(wintime)


class _MMVAD_SHORT(objects.Struct):
    """A class that represents process virtual memory ranges. Each instance
    is a node in a binary tree structure and is pointed to by VadRoot."""

    @functools.lru_cache(maxsize = None)
    def get_tag(self):
        vad_address = self.vol.offset

        # the offset is different on 32 and 64 bits
        symbol_table_name = self.vol.type_name.split(constants.BANG)[0]
        if not symbols.utility.symbol_table_is_64bit(self.context, symbol_table_name):
            vad_address -= 4
        else:
            vad_address -= 12

        try:
            # TODO: instantiate a _POOL_HEADER and return PoolTag
            bytesobj = self._context.object(symbol_table_name + constants.BANG + "bytes",
                                            layer_name = self.vol.layer_name,
                                            offset = vad_address,
                                            native_layer_name = self.vol.native_layer_name,
                                            length = 4)

            return bytesobj.decode()
        except exceptions.InvalidAddressException:
            return None
        except UnicodeDecodeError:
            return None

    def traverse(self, visited = None, depth = 0):
        """Traverse the VAD tree, determining each underlying VAD node type by looking
        up the pool tag for the structure and then casting into a new object."""

        # TODO: this is an arbitrary limit chosen based on past observations
        if depth > 100:
            vollog.log(constants.LOGLEVEL_VVV, "Vad tree is too deep, something went wrong!")
            raise RuntimeError("Vad tree is too deep")

        if visited == None:
            visited = set()

        vad_address = self.vol.offset

        if vad_address in visited:
            vollog.log(constants.LOGLEVEL_VVV, "VAD node already seen!")
            return

        visited.add(vad_address)
        tag = self.get_tag()

        if tag in ["VadS", "VadF"]:
            target = "_MMVAD_SHORT"
        elif tag != None and tag.startswith("Vad"):
            target = "_MMVAD"
        elif depth == 0:
            # the root node at depth 0 is allowed to not have a tag
            # but we still want to continue and access its right & left child
            target = None
        else:
            # any node other than the root that doesn't have a recognized tag
            # is just garbage and we skip the node entirely
            vollog.log(constants.LOGLEVEL_VVV,
                       "Skipping VAD at {} depth {} with tag {}".format(self.vol.offset, depth, tag))
            return

        if target:
            vad_object = self.cast(target)
            yield vad_object

        for vad_node in self.get_left_child().dereference().traverse(visited, depth + 1):
            yield vad_node

        for vad_node in self.get_right_child().dereference().traverse(visited, depth + 1):
            yield vad_node

    def get_right_child(self):
        """Get the right child member"""

        if self.has_member("RightChild"):
            return self.RightChild

        elif self.has_member("Right"):
            return self.Right

        raise AttributeError("Unable to find the right child member")

    def get_left_child(self):
        """Get the left child member"""

        if self.has_member("LeftChild"):
            return self.LeftChild

        elif self.has_member("Left"):
            return self.Left

        raise AttributeError("Unable to find the left child member")

    def get_parent(self):
        """Get the VAD's parent member"""

        # this is for xp and 2003
        if self.has_member("Parent"):
            return self.Parent

        # this is for vista through windows 7
        elif self.has_member("u1") and self.u1.has_member("Parent"):
            return self.u1.Parent & ~0x3

        # this is for windows 8 and 10
        elif self.has_member("VadNode"):

            if self.VadNode.has_member("u1"):
                return self.VadNode.u1.Parent & ~0x3

            elif self.VadNode.has_member("ParentValue"):
                return self.VadNode.ParentValue & ~0x3

        # also for windows 8 and 10
        elif self.has_member("Core"):

            if self.Core.VadNode.has_member("u1"):
                return self.Core.VadNode.u1.Parent & ~0x3

            elif self.Core.VadNode.has_member("ParentValue"):
                return self.Core.VadNode.ParentValue & ~0x3

        raise AttributeError("Unable to find the parent member")

    def get_start(self):
        """Get the VAD's starting virtual address"""

        if self.has_member("StartingVpn"):

            if self.has_member("StartingVpnHigh"):
                return (self.StartingVpn << 12) | (self.StartingVpnHigh << 44)
            else:
                return self.StartingVpn << 12

        elif self.has_member("Core"):

            if self.Core.has_member("StartingVpnHigh"):
                return (self.Core.StartingVpn << 12) | (self.Core.StartingVpnHigh << 44)
            else:
                return self.Core.StartingVpn << 12

        raise AttributeError("Unable to find the starting VPN member")

    def get_end(self):
        """Get the VAD's ending virtual address"""

        if self.has_member("EndingVpn"):

            if self.has_member("EndingVpnHigh"):
                return (self.EndingVpn << 12) | (self.EndingVpnHigh << 44)
            else:
                return ((self.EndingVpn + 1) << 12) - 1

        elif self.has_member("Core"):

            if self.Core.has_member("EndingVpnHigh"):
                return (self.Core.EndingVpn << 12) | (self.Core.EndingVpnHigh << 44)
            else:
                return ((self.Core.EndingVpn + 1) << 12) - 1

        raise AttributeError("Unable to find the ending VPN member")

    def get_commit_charge(self):
        """Get the VAD's commit charge (number of committed pages)"""

        if self.has_member("u1") and self.u1.has_member("VadFlags1"):
            return self.u1.VadFlags1.CommitCharge

        elif self.has_member("u") and self.u.has_member("VadFlags"):
            return self.u.VadFlags.CommitCharge

        elif self.has_member("Core"):
            return self.Core.u1.VadFlags1.CommitCharge

        raise AttributeError("Unable to find the commit charge member")

    def get_private_memory(self):
        """Get the VAD's private memory setting"""

        if self.has_member("u1") and self.u1.has_member("VadFlags1") and self.u1.VadFlags1.has_member("PrivateMemory"):
            return self.u1.VadFlags1.PrivateMemory

        elif self.has_member("u") and self.u.has_member("VadFlags") and self.u.VadFlags.has_member("PrivateMemory"):
            return self.u.VadFlags.PrivateMemory

        elif self.has_member("Core"):
            if (self.Core.has_member("u1") and self.Core.u1.has_member(
                    "VadFlags1") and self.Core.u1.VadFlags1.has_member("PrivateMemory")):
                return self.Core.u1.VadFlags1.PrivateMemory

            elif (self.Core.has_member("u") and self.Core.u.has_member("VadFlags") and self.Core.u.VadFlags.has_member(
                    "PrivateMemory")):
                return self.Core.u.VadFlags.PrivateMemory

        raise AttributeError("Unable to find the private memory member")

    def get_protection(self, protect_values, winnt_protections):
        """Get the VAD's protection constants as a string"""

        protect = None

        if self.has_member("u"):
            protect = self.u.VadFlags.Protection

        elif self.has_member("Core"):
            protect = self.Core.u.VadFlags.Protection

        try:
            value = protect_values[protect]
        except IndexError:
            value = 0

        names = []

        for name, mask in winnt_protections.items():
            if value & mask != 0:
                names.append(name)

        return "|".join(names)

    def get_file_name(self):
        """Only long(er) vads have mapped files"""
        return renderers.NotApplicableValue()


class _MMVAD(_MMVAD_SHORT):
    """A version of the process virtual memory range structure that contains
    additional fields necessary to map files from disk."""

    def get_file_name(self):
        """Get the name of the file mapped into the memory range (if any)"""

        file_name = renderers.NotApplicableValue()

        try:
            # this is for xp and 2003
            if self.has_member("ControlArea"):
                file_name = self.ControlArea.FilePointer.FileName.get_string()

            # this is for vista through windows 7
            else:
                file_name = self.Subsection.ControlArea.FilePointer.dereference().cast(
                    "_FILE_OBJECT").FileName.get_string()

        except exceptions.PagedInvalidAddressException:
            pass

        return file_name


class _EX_FAST_REF(objects.Struct):
    """This is a standard Windows structure that stores a pointer to an
    object but also leverages the least significant bits to encode additional
    details. When dereferencing the pointer, we need to strip off the extra bits."""

    def dereference(self) -> interfaces.objects.ObjectInterface:

        if constants.BANG not in self.vol.type_name:
            raise ValueError("Invalid symbol table name syntax (no {} found)".format(constants.BANG))

        # the mask value is different on 32 and 64 bits
        symbol_table_name = self.vol.type_name.split(constants.BANG)[0]
        if not symbols.utility.symbol_table_is_64bit(self._context, symbol_table_name):
            max_fast_ref = 7
        else:
            max_fast_ref = 15

        return self._context.object(symbol_table_name + constants.BANG + "pointer",
                                    layer_name = self.vol.layer_name,
                                    offset = self.Object & ~max_fast_ref,
                                    native_layer_name = self.vol.native_layer_name)


class ExecutiveObject(interfaces.objects.ObjectInterface):
    """This is used as a "mixin" that provides all kernel executive
    objects with a means of finding their own object header."""

    def object_header(self) -> '_OBJECT_HEADER':
        if constants.BANG not in self.vol.type_name:
            raise ValueError("Invalid symbol table name syntax (no {} found)".format(constants.BANG))
        symbol_table_name = self.vol.type_name.split(constants.BANG)[0]
        body_offset = self._context.symbol_space.get_type(
            symbol_table_name + constants.BANG + "_OBJECT_HEADER").relative_child_offset("Body")
        return self._context.object(symbol_table_name + constants.BANG + "_OBJECT_HEADER",
                                    layer_name = self.vol.layer_name,
                                    offset = self.vol.offset - body_offset,
                                    native_layer_name = self.vol.native_layer_name)


class _CM_KEY_BODY(objects.Struct):
    """This represents an open handle to a registry key and
    is not tied to the registry hive file format on disk."""

    def _skip_key_hive_entry_path(self, kcb_flags):
        """Win10 14393 introduced an extra path element that it skips
        over by checking for Flags that contain KEY_HIVE_ENTRY"""

        # _CM_KEY_BODY.Trans introduced in Win10 14393
        if hasattr(self, "Trans") and RegKeyFlags.KEY_HIVE_ENTRY & kcb_flags == RegKeyFlags.KEY_HIVE_ENTRY:
            return True

        return False

    def get_full_key_name(self) -> str:
        output = []
        kcb = self.KeyControlBlock
        while kcb.ParentKcb:
            if kcb.NameBlock.Name == None:
                break

            if self._skip_key_hive_entry_path(kcb.Flags):
                kcb = kcb.ParentKcb
                if not kcb:
                    break

            output.append(kcb.NameBlock.Name.cast("string",
                                                  encoding = "utf8",
                                                  max_length = kcb.NameBlock.NameLength,
                                                  errors = "replace"))
            kcb = kcb.ParentKcb
        return "\\".join(reversed(output))


class _DEVICE_OBJECT(objects.Struct, ExecutiveObject):
    """A class for kernel device objects."""

    def get_device_name(self) -> str:
        header = self.object_header()
        return header.NameInfo.Name.String  # type: ignore


class _FILE_OBJECT(objects.Struct, ExecutiveObject):
    def file_name_with_device(self) -> typing.Union[str, interfaces.renderers.BaseAbsentValue]:
        name = renderers.UnreadableValue()  # type: typing.Union[str, interfaces.renderers.BaseAbsentValue]

        if self._context.memory[self.vol.layer_name].is_valid(self.DeviceObject):
            name = "\\Device\\{}".format(self.DeviceObject.get_device_name())

        try:
            name += self.FileName.String
        except exceptions.PagedInvalidAddressException:
            pass

        return name


class _OBJECT_HEADER(objects.Struct):
    """A class for the headers for executive kernel objects, which contains
    quota information, ownership details, naming data, and ACLs."""

    @property
    def NameInfo(self) -> interfaces.objects.ObjectInterface:
        if constants.BANG not in self.vol.type_name:
            raise ValueError("Invalid symbol table name syntax (no {} found)".format(constants.BANG))

        symbol_table_name = self.vol.type_name.split(constants.BANG)[0]

        try:
            header_offset = ord(self.NameInfoOffset)
        except AttributeError:
            # http://codemachine.com/article_objectheader.html (Windows 7 and later)
            name_info_bit = 0x2

            layer = self._context.memory[self.vol.native_layer_name]
            kvo = layer.config.get("kernel_virtual_offset", None)

            if kvo == None:
                raise AttributeError("Could not find kernel_virtual_offset for layer: {}".format(self.vol.layer_name))

            ntkrnlmp = self._context.module(symbol_table_name, layer_name = self.vol.layer_name, offset = kvo)
            address = ntkrnlmp.get_symbol("ObpInfoMaskToOffset").address
            calculated_index = ord(self.InfoMask) & (name_info_bit | (name_info_bit - 1))

            header_offset = self._context.object(symbol_table_name + constants.BANG + "unsigned char",
                                                 layer_name = self.vol.native_layer_name,
                                                 offset = address + calculated_index)

        header = self._context.object(symbol_table_name + constants.BANG + "_OBJECT_HEADER_NAME_INFO",
                                      layer_name = self.vol.layer_name,
                                      offset = self.vol.offset - header_offset,
                                      native_layer_name = self.vol.native_layer_name)
        return header


class _ETHREAD(objects.Struct):
    """A class for executive thread objects."""

    def owning_process(self, kernel_layer: str = None) -> interfaces.objects.ObjectInterface:
        """Return the EPROCESS that owns this thread"""
        return self.ThreadsProcess.dereference(kernel_layer)


class _UNICODE_STRING(objects.Struct):
    """A class for Windows unicode string structures."""

    def get_string(self) -> interfaces.objects.ObjectInterface:
        # We explicitly do *not* catch errors here, we allow an exception to be thrown
        # (otherwise there's no way to determine anything went wrong)
        # It's up to the user of this method to catch exceptions
        return self.Buffer.dereference().cast("string", max_length = self.Length, errors = "replace",
                                              encoding = "utf16")

    String = property(get_string)


class _EPROCESS(generic.GenericIntelProcess, ExecutiveObject):
    """A class for executive kernel processes objects."""

    def add_process_layer(self,
                          config_prefix: str = None,
                          preferred_name: str = None):
        """Constructs a new layer based on the process's DirectoryTableBase"""

        parent_layer = self._context.memory[self.vol.layer_name]

        if not isinstance(parent_layer, intel.Intel):
            # We can't get bits_per_register unless we're an intel space (since that's not defined at the higher layer)
            raise TypeError("Parent layer is not a translation layer, unable to construct process layer")

        # Presumably for 64-bit systems, the DTB is defined as an array, rather than an unsigned long long
        dtb = 0  # type: int
        if isinstance(self.Pcb.DirectoryTableBase, objects.Array):
            dtb = self.Pcb.DirectoryTableBase.cast("unsigned long long")
        else:
            dtb = self.Pcb.DirectoryTableBase
        dtb = dtb & ((1 << parent_layer.bits_per_register) - 1)

        # Add the constructed layer and return the name
        return self._add_process_layer(self._context, dtb, config_prefix, preferred_name)

    def load_order_modules(self) -> typing.Iterable[int]:
        """Generator for DLLs in the order that they were loaded"""

        if constants.BANG not in self.vol.type_name:
            raise ValueError("Invalid symbol table name syntax (no {} found)".format(constants.BANG))

        proc_layer_name = self.add_process_layer()

        proc_layer = self._context.memory[proc_layer_name]
        if not proc_layer.is_valid(self.Peb):
            return

        sym_table = self.vol.type_name.split(constants.BANG)[0]
        peb = self._context.object("{}{}_PEB".format(sym_table, constants.BANG),
                                   layer_name = proc_layer_name,
                                   offset = self.Peb)

        for entry in peb.Ldr.InLoadOrderModuleList.to_list(
                "{}{}_LDR_DATA_TABLE_ENTRY".format(sym_table, constants.BANG), "InLoadOrderLinks"):
            yield entry

    def get_handle_count(self):
        try:
            if self.has_member("ObjectTable"):
                if self.ObjectTable.has_member("HandleCount"):
                    return self.ObjectTable.HandleCount

        except exceptions.PagedInvalidAddressException:
            vollog.log(constants.LOGLEVEL_VVV,
                       "Cannot access _EPROCESS.ObjectTable.HandleCount at {0:#x}".format(self.vol.offset))

        return renderers.UnreadableValue()

    def get_session_id(self):
        try:
            if self.has_member("Session"):
                if self.Session == 0:
                    return renderers.NotApplicableValue()

                layer_name = self.vol.layer_name
                symbol_table_name = self.get_symbol_table().name
                kvo = self._context.memory[layer_name].config['kernel_virtual_offset']
                ntkrnlmp = self._context.module(symbol_table_name,
                                                layer_name = layer_name,
                                                offset = kvo,
                                                native_layer_name = self.vol.native_layer_name)
                session = ntkrnlmp.object(type_name = "_MM_SESSION_SPACE", offset = self.Session)

                if session.has_member("SessionId"):
                    return session.SessionId

        except exceptions.PagedInvalidAddressException:
            vollog.log(constants.LOGLEVEL_VVV,
                       "Cannot access _EPROCESS.Session.SessionId at {0:#x}".format(self.vol.offset))

        return renderers.UnreadableValue()

    def get_create_time(self):
        return objects.utility.wintime_to_datetime(self.CreateTime.QuadPart)

    def get_exit_time(self):
        return objects.utility.wintime_to_datetime(self.ExitTime.QuadPart)

    def get_wow_64_process(self):
        if self.has_member("Wow64Process"):
            return self.Wow64Process

        elif self.has_member("WoW64Process"):
            return self.WoW64Process

        raise AttributeError("Unable to find Wow64Process")

    def get_is_wow64(self):
        try:
            value = self.get_wow_64_process()
        except AttributeError:
            return False

        return value != 0 and value != None

    def get_vad_root(self):

        # windows 8 and 2012 (_MM_AVL_TABLE)
        if self.VadRoot.has_member("BalancedRoot"):
            return self.VadRoot.BalancedRoot

        # windows 8.1 and windows 10 (_RTL_AVL_TREE)
        elif self.VadRoot.has_member("Root"):
            return self.VadRoot.Root.dereference()  # .cast("_MMVAD")

        else:
            # windows xp and 2003
            return self.VadRoot.dereference().cast("_MMVAD")


class _LIST_ENTRY(objects.Struct, collections.abc.Iterable):
    """A class for double-linked lists on Windows."""

    def to_list(self,
                symbol_type: str,
                member: str,
                forward: bool = True,
                sentinel: bool = True,
                layer: typing.Optional[str] = None) -> typing.Iterator[interfaces.objects.ObjectInterface]:
        """Returns an iterator of the entries in the list"""

        layer = layer or self.vol.layer_name

        relative_offset = self._context.symbol_space.get_type(symbol_type).relative_child_offset(member)

        direction = 'Blink'
        if forward:
            direction = 'Flink'
        link = getattr(self, direction).dereference()

        if not sentinel:
            yield self._context.object(symbol_type,
                                       layer,
                                       offset = self.vol.offset - relative_offset,
                                       native_layer_name = layer or self.vol.native_layer_name)

        seen = {self.vol.offset}
        while link.vol.offset not in seen:

            obj = self._context.object(symbol_type,
                                       layer,
                                       offset = link.vol.offset - relative_offset,
                                       native_layer_name = layer or self.vol.native_layer_name)
            yield obj

            seen.add(link.vol.offset)
            link = getattr(link, direction).dereference()

    def __iter__(self) -> typing.Iterator[interfaces.objects.ObjectInterface]:
        return self.to_list(self.vol.parent.vol.type_name, self.vol.member_name)
