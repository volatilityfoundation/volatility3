# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl_v1.0
#

import collections.abc
import datetime
import functools
import logging
from typing import Iterable, Iterator, Optional, Union, Dict

from volatility.framework import constants, exceptions, interfaces, objects, renderers, symbols
from volatility.framework.layers import intel
from volatility.framework.renderers import conversion
from volatility.framework.symbols import generic

vollog = logging.getLogger(__name__)

# Keep these in a basic module, to prevent import cycles when symbol providers require them


class _POOL_HEADER(objects.StructType):
    """A kernel pool allocation header.

    Exists at the base of the allocation and provides a tag that we can
    scan for.
    """

    def get_object(self,
                   type_name: str,
                   type_map: dict,
                   use_top_down: bool,
                   native_layer_name: Optional[str] = None,
                   object_type: Optional[str] = None,
                   cookie: Optional[int] = None) -> Optional[interfaces.objects.ObjectInterface]:
        """Carve an object or data structure from a kernel pool allocation.

        :param type_name: the data structure type name
        :param native_layer_name: the name of the layer where the data originally lived
        :param object_type: the object type (executive kernel objects only)
        :return:
        """

        symbol_table_name = self.vol.type_name.split(constants.BANG)[0]
        if constants.BANG in type_name:
            symbol_table_name, type_name = type_name.split(constants.BANG)[0:2]

        object_header_type = self._context.symbol_space.get_type(symbol_table_name + constants.BANG + "_OBJECT_HEADER")
        infomask_offset = object_header_type.relative_child_offset('InfoMask')

        pool_header_size = self.vol.size

        # if there is no object type, then just instantiate a structure
        if object_type is None:
            mem_object = self._context.object(symbol_table_name + constants.BANG + type_name,
                                              layer_name = self.vol.layer_name,
                                              offset = self.vol.offset + pool_header_size,
                                              native_layer_name = native_layer_name)
            return mem_object

        # otherwise we have an executive object in the pool
        else:
            if symbols.symbol_table_is_64bit(self._context, symbol_table_name):
                alignment = 16
            else:
                alignment = 8

            lengths_of_optional_headers = self._calculate_optional_header_lengths(self._context, symbol_table_name)
            max_optional_headers_length = sum(lengths_of_optional_headers)

            # use the top down approach for windows 8 and later
            if use_top_down:
                # define the starting and ending bounds for the scan
                start_offset = self.vol.offset + pool_header_size
                addr_limit = min(max_optional_headers_length, self.BlockSize * alignment)

                # A single read is better than lots of little one-byte reads.
                # We're ok padding this, because the byte we'd check would be 0 which would only be valid if there
                # were no optional headers in the first place (ie, if we read too much for headers that don't exist,
                # but the bit we could read were valid)
                infomask_data = self._context.layers[self.vol.layer_name].read(
                    start_offset + infomask_offset, addr_limit, pad = True)

                for addr in range(0, addr_limit, alignment):
                    infomask_value = infomask_data[addr]

                    optional_headers_length = 0
                    for i in range(len(lengths_of_optional_headers)):
                        if infomask_value & (1 << i):
                            optional_headers_length += lengths_of_optional_headers[i]

                    if optional_headers_length != addr:
                        continue

                    try:

                        object_header = self._context.object(
                            symbol_table_name + constants.BANG + "_OBJECT_HEADER",
                            layer_name = self.vol.layer_name,
                            offset = addr + start_offset,
                            native_layer_name = native_layer_name)

                        if not object_header.is_valid():
                            continue

                        object_type_string = object_header.get_object_type(type_map, cookie)
                        if object_type_string == object_type:

                            mem_object = object_header.Body.cast(symbol_table_name + constants.BANG + type_name)
                            if mem_object.is_valid():
                                return mem_object

                    except (TypeError, exceptions.InvalidAddressException):
                        pass

            # use the bottom up approach for windows 7 and earlier
            else:
                type_size = self._context.symbol_space.get_type(symbol_table_name + constants.BANG + type_name).size
                rounded_size = conversion.round(type_size, alignment, up = True)

                mem_object = self._context.object(symbol_table_name + constants.BANG + type_name,
                                                  layer_name = self.vol.layer_name,
                                                  offset = self.vol.offset + self.BlockSize * alignment - rounded_size,
                                                  native_layer_name = native_layer_name)

                object_header = mem_object.object_header()

                try:
                    object_type_string = object_header.get_object_type(type_map, cookie)
                    if object_type_string == object_type:
                        return mem_object
                    else:
                        return None
                except (TypeError, exceptions.InvalidAddressException):
                    return None
        return None

    @classmethod
    @functools.lru_cache()
    def _calculate_optional_header_lengths(cls, context: interfaces.context.ContextInterface,
                                           symbol_table_name: str) -> List[int]:
        sizes = []
        for header in [
                'CREATOR_INFO', 'NAME_INFO', 'HANDLE_INFO', 'QUOTA_INFO', 'PROCESS_INFO', 'AUDIT_INFO', 'EXTENDED_INFO',
                'HANDLE_REVOCATION_INFO', 'PADDING_INFO'
        ]:
            try:
                type_name = "{}{}_OBJECT_HEADER_{}".format(symbol_table_name, constants.BANG, header)
                header_type = context.symbol_space.get_type(type_name)
                sizes.append(header_type.size)
            except:
                # Some of these may not exist, for example:
                #   if build < 9200: PADDING_INFO else: AUDIT_INFO
                #   if build == 10586: HANDLE_REVOCATION_INFO else EXTENDED_INFO
                # based on what's present and what's not, this list should be the right order and the right length
                pass
        return sizes

class _KSYSTEM_TIME(objects.StructType):
    """A system time structure that stores a high and low part."""

    def get_time(self):
        wintime = (self.High1Time << 32) | self.LowPart
        return conversion.wintime_to_datetime(wintime)


class _MMVAD_SHORT(objects.StructType):
    """A class that represents process virtual memory ranges.

    Each instance is a node in a binary tree structure and is pointed to
    by VadRoot.
    """

    @functools.lru_cache(maxsize = None)
    def get_tag(self):
        vad_address = self.vol.offset

        # the offset is different on 32 and 64 bits
        symbol_table_name = self.vol.type_name.split(constants.BANG)[0]
        if not symbols.symbol_table_is_64bit(self._context, symbol_table_name):
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
        """Traverse the VAD tree, determining each underlying VAD node type by
        looking up the pool tag for the structure and then casting into a new
        object."""

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
        """Get the right child member."""

        if self.has_member("RightChild"):
            return self.RightChild

        elif self.has_member("Right"):
            return self.Right

        raise AttributeError("Unable to find the right child member")

    def get_left_child(self):
        """Get the left child member."""

        if self.has_member("LeftChild"):
            return self.LeftChild

        elif self.has_member("Left"):
            return self.Left

        raise AttributeError("Unable to find the left child member")

    def get_parent(self):
        """Get the VAD's parent member."""

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
        """Get the VAD's starting virtual address."""

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
        """Get the VAD's ending virtual address."""

        if self.has_member("EndingVpn"):

            if self.has_member("EndingVpnHigh"):
                return (((self.EndingVpn + 1) << 12) | (self.EndingVpnHigh << 44)) - 1
            else:
                return ((self.EndingVpn + 1) << 12) - 1

        elif self.has_member("Core"):
            if self.Core.has_member("EndingVpnHigh"):
                return (((self.Core.EndingVpn + 1) << 12) | (self.Core.EndingVpnHigh << 44)) - 1
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
        """Get the VAD's private memory setting."""

        if self.has_member("u1") and self.u1.has_member("VadFlags1") and self.u1.VadFlags1.has_member("PrivateMemory"):
            return self.u1.VadFlags1.PrivateMemory

        elif self.has_member("u") and self.u.has_member("VadFlags") and self.u.VadFlags.has_member("PrivateMemory"):
            return self.u.VadFlags.PrivateMemory

        elif self.has_member("Core"):
            if (self.Core.has_member("u1") and self.Core.u1.has_member("VadFlags1")
                    and self.Core.u1.VadFlags1.has_member("PrivateMemory")):
                return self.Core.u1.VadFlags1.PrivateMemory

            elif (self.Core.has_member("u") and self.Core.u.has_member("VadFlags")
                  and self.Core.u.VadFlags.has_member("PrivateMemory")):
                return self.Core.u.VadFlags.PrivateMemory

        raise AttributeError("Unable to find the private memory member")

    def get_protection(self, protect_values, winnt_protections):
        """Get the VAD's protection constants as a string."""

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
        """Only long(er) vads have mapped files."""
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


class _EX_FAST_REF(objects.StructType):
    """This is a standard Windows structure that stores a pointer to an object
    but also leverages the least significant bits to encode additional details.

    When dereferencing the pointer, we need to strip off the extra bits.
    """

    def dereference(self) -> interfaces.objects.ObjectInterface:

        if constants.BANG not in self.vol.type_name:
            raise ValueError("Invalid symbol table name syntax (no {} found)".format(constants.BANG))

        # the mask value is different on 32 and 64 bits
        symbol_table_name = self.vol.type_name.split(constants.BANG)[0]
        if not symbols.symbol_table_is_64bit(self._context, symbol_table_name):
            max_fast_ref = 7
        else:
            max_fast_ref = 15

        return self._context.object(symbol_table_name + constants.BANG + "pointer",
                                    layer_name = self.vol.layer_name,
                                    offset = self.Object & ~max_fast_ref,
                                    native_layer_name = self.vol.native_layer_name)


class ExecutiveObject(interfaces.objects.ObjectInterface):
    """This is used as a "mixin" that provides all kernel executive objects
    with a means of finding their own object header."""

    def object_header(self) -> '_OBJECT_HEADER':
        if constants.BANG not in self.vol.type_name:
            raise ValueError("Invalid symbol table name syntax (no {} found)".format(constants.BANG))
        symbol_table_name = self.vol.type_name.split(constants.BANG)[0]
        body_offset = self._context.symbol_space.get_type(symbol_table_name + constants.BANG +
                                                          "_OBJECT_HEADER").relative_child_offset("Body")
        return self._context.object(symbol_table_name + constants.BANG + "_OBJECT_HEADER",
                                    layer_name = self.vol.layer_name,
                                    offset = self.vol.offset - body_offset,
                                    native_layer_name = self.vol.native_layer_name)


class _DEVICE_OBJECT(objects.StructType, ExecutiveObject):
    """A class for kernel device objects."""

    def get_device_name(self) -> str:
        header = self.object_header()
        return header.NameInfo.Name.String  # type: ignore


class _DRIVER_OBJECT(objects.StructType, ExecutiveObject):
    """A class for kernel driver objects."""

    def get_driver_name(self) -> str:
        header = self.object_header()
        return header.NameInfo.Name.String  # type: ignore

    def is_valid(self) -> bool:
        """Determine if the object is valid."""
        return True


class _OBJECT_SYMBOLIC_LINK(objects.StructType, ExecutiveObject):
    """A class for kernel link objects."""

    def get_link_name(self) -> str:
        header = self.object_header()
        return header.NameInfo.Name.String  # type: ignore

    def is_valid(self) -> bool:
        """Determine if the object is valid."""
        return True

    def get_create_time(self):
        return conversion.wintime_to_datetime(self.CreationTime.QuadPart)


class _FILE_OBJECT(objects.StructType, ExecutiveObject):
    """A class for windows file objects."""

    def is_valid(self) -> bool:
        """Determine if the object is valid."""
        return self.FileName.Length > 0 and self._context.layers[self.vol.layer_name].is_valid(self.FileName.Buffer)

    def file_name_with_device(self) -> Union[str, interfaces.renderers.BaseAbsentValue]:
        name = renderers.UnreadableValue()  # type: Union[str, interfaces.renderers.BaseAbsentValue]

        if self._context.layers[self.vol.layer_name].is_valid(self.DeviceObject):
            name = "\\Device\\{}".format(self.DeviceObject.get_device_name())

        try:
            name += self.FileName.String
        except (TypeError, exceptions.PagedInvalidAddressException):
            pass

        return name


class _KMUTANT(objects.StructType, ExecutiveObject):
    """A class for windows mutant objects."""

    def is_valid(self) -> bool:
        """Determine if the object is valid."""
        return True

    def get_name(self) -> str:
        """Get the object's name from the object header."""
        header = self.object_header()
        return header.NameInfo.Name.String  # type: ignore


class _OBJECT_HEADER(objects.StructType):
    """A class for the headers for executive kernel objects, which contains
    quota information, ownership details, naming data, and ACLs."""

    def is_valid(self) -> bool:
        """Determine if the object is valid."""

        # if self.InfoMask > 0x48:
        #    return False

        try:
            if self.PointerCount > 0x1000000 or self.PointerCount < 0:
                return False
        except exceptions.InvalidAddressException:
            return False

        return True

    def get_object_type(self, type_map: Dict[int, str], cookie: int = None) -> Optional[str]:
        """Across all Windows versions, the _OBJECT_HEADER embeds details on
        the type of object (i.e. process, file) but the way its embedded
        differs between versions.

        This API abstracts away those details.
        """

        if self.vol.get('object_header_object_type', None) is not None:
            return self.vol.object_header_object_type

        try:
            # vista and earlier have a Type member
            self._vol['object_header_object_type'] = self.Type.Name.String
        except AttributeError:
            # windows 7 and later have a TypeIndex, but windows 10
            # further encodes the index value with nt1!ObHeaderCookie
            try:
                type_index = ((self.vol.offset >> 8) ^ cookie ^ self.TypeIndex) & 0xFF
            except (AttributeError, TypeError):
                type_index = self.TypeIndex

            self._vol['object_header_object_type'] = type_map.get(type_index)
        return self.vol.object_header_object_type

    @property
    def NameInfo(self) -> interfaces.objects.ObjectInterface:
        if constants.BANG not in self.vol.type_name:
            raise ValueError("Invalid symbol table name syntax (no {} found)".format(constants.BANG))

        symbol_table_name = self.vol.type_name.split(constants.BANG)[0]

        try:
            header_offset = self.NameInfoOffset
        except AttributeError:
            # http://codemachine.com/article_objectheader.html (Windows 7 and later)
            name_info_bit = 0x2

            layer = self._context.layers[self.vol.native_layer_name]
            kvo = layer.config.get("kernel_virtual_offset", None)

            if kvo == None:
                raise AttributeError("Could not find kernel_virtual_offset for layer: {}".format(self.vol.layer_name))

            ntkrnlmp = self._context.module(symbol_table_name, layer_name = self.vol.layer_name, offset = kvo)
            address = ntkrnlmp.get_symbol("ObpInfoMaskToOffset").address
            calculated_index = self.InfoMask & (name_info_bit | (name_info_bit - 1))

            header_offset = self._context.object(symbol_table_name + constants.BANG + "unsigned char",
                                                 layer_name = self.vol.native_layer_name,
                                                 offset = kvo + address + calculated_index)

        header = self._context.object(symbol_table_name + constants.BANG + "_OBJECT_HEADER_NAME_INFO",
                                      layer_name = self.vol.layer_name,
                                      offset = self.vol.offset - header_offset,
                                      native_layer_name = self.vol.native_layer_name)
        return header


class _ETHREAD(objects.StructType):
    """A class for executive thread objects."""

    def owning_process(self, kernel_layer: str = None) -> interfaces.objects.ObjectInterface:
        """Return the EPROCESS that owns this thread."""
        return self.ThreadsProcess.dereference(kernel_layer)


class _UNICODE_STRING(objects.StructType):
    """A class for Windows unicode string structures."""

    def get_string(self) -> interfaces.objects.ObjectInterface:
        # We explicitly do *not* catch errors here, we allow an exception to be thrown
        # (otherwise there's no way to determine anything went wrong)
        # It's up to the user of this method to catch exceptions
        return self.Buffer.dereference().cast("string",
                                              max_length = self.Length,
                                              errors = "replace",
                                              encoding = "utf16")

    String = property(get_string)


class _EPROCESS(generic.GenericIntelProcess, ExecutiveObject):
    """A class for executive kernel processes objects."""

    def is_valid(self) -> bool:
        """Determine if the object is valid."""

        try:
            name = objects.utility.array_to_string(self.ImageFileName)
            if not name or len(name) == 0 or name[0] == "\x00":
                return False

            # The System/PID 4 process has no create time
            if not (str(name) == "System" and self.UniqueProcessId == 4):
                if self.CreateTime.QuadPart == 0:
                    return False

                ctime = self.get_create_time()
                if not isinstance(ctime, datetime.datetime):
                    return False

                if not (1998 < ctime.year < 2030):
                    return False

            # NT pids are divisible by 4
            if self.UniqueProcessId % 4 != 0:
                return False

            if self.Pcb.DirectoryTableBase == 0:
                return False

            # check for all 0s besides the PCID entries
            if self.Pcb.DirectoryTableBase & ~0xfff == 0:
                return False

            ## TODO: we can also add the thread Flink and Blink tests if necessary

        except exceptions.InvalidAddressException:
            return False

        return True

    def add_process_layer(self, config_prefix: str = None, preferred_name: str = None):
        """Constructs a new layer based on the process's DirectoryTableBase."""

        parent_layer = self._context.layers[self.vol.layer_name]

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

        if preferred_name is None:
            preferred_name = self.vol.layer_name + "_Process{}".format(self.UniqueProcessId)

        # Add the constructed layer and return the name
        return self._add_process_layer(self._context, dtb, config_prefix, preferred_name)

    def load_order_modules(self) -> Iterable[int]:
        """Generator for DLLs in the order that they were loaded."""

        if constants.BANG not in self.vol.type_name:
            raise ValueError("Invalid symbol table name syntax (no {} found)".format(constants.BANG))

        proc_layer_name = self.add_process_layer()

        proc_layer = self._context.layers[proc_layer_name]
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

                symbol_table_name = self.get_symbol_table().name
                kvo = self._context.layers[self.vol.native_layer_name].config['kernel_virtual_offset']
                ntkrnlmp = self._context.module(symbol_table_name,
                                                layer_name = self.vol.native_layer_name,
                                                offset = kvo,
                                                native_layer_name = self.vol.native_layer_name)
                session = ntkrnlmp.object(object_type = "_MM_SESSION_SPACE", offset = self.Session, absolute = True)

                if session.has_member("SessionId"):
                    return session.SessionId

        except exceptions.PagedInvalidAddressException:
            vollog.log(constants.LOGLEVEL_VVV,
                       "Cannot access _EPROCESS.Session.SessionId at {0:#x}".format(self.vol.offset))

        return renderers.UnreadableValue()

    def get_create_time(self):
        return conversion.wintime_to_datetime(self.CreateTime.QuadPart)

    def get_exit_time(self):
        return conversion.wintime_to_datetime(self.ExitTime.QuadPart)

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


class _LIST_ENTRY(objects.StructType, collections.abc.Iterable):
    """A class for double-linked lists on Windows."""

    def to_list(self,
                symbol_type: str,
                member: str,
                forward: bool = True,
                sentinel: bool = True,
                layer: Optional[str] = None) -> Iterator[interfaces.objects.ObjectInterface]:
        """Returns an iterator of the entries in the list."""

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

    def __iter__(self) -> Iterator[interfaces.objects.ObjectInterface]:
        return self.to_list(self.vol.parent.vol.type_name, self.vol.member_name)
