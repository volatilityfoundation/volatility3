# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

import collections.abc
import datetime
import functools
import logging
from typing import Iterable, Iterator, Optional, Union

from volatility.framework import constants, exceptions, interfaces, objects, renderers, symbols
from volatility.framework.layers import intel
from volatility.framework.renderers import conversion
from volatility.framework.symbols import generic
from volatility.framework.symbols.windows.extensions import pool

vollog = logging.getLogger(__name__)

# Keep these in a basic module, to prevent import cycles when symbol providers require them


class KSYSTEM_TIME(objects.StructType):
    """A system time structure that stores a high and low part."""

    def get_time(self):
        wintime = (self.High1Time << 32) | self.LowPart
        return conversion.wintime_to_datetime(wintime)


class MMVAD_SHORT(objects.StructType):
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

        if visited is None:
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

        try:
            for vad_node in self.get_left_child().dereference().traverse(visited, depth + 1):
                yield vad_node
        except exceptions.InvalidAddressException as excp:
            vollog.log(constants.LOGLEVEL_VVV, "Invalid address on LeftChild: {0:#x}".format(excp.invalid_address))

        try:
            for vad_node in self.get_right_child().dereference().traverse(visited, depth + 1):
                yield vad_node
        except exceptions.InvalidAddressException as excp:
            vollog.log(constants.LOGLEVEL_VVV, "Invalid address on RightChild: {0:#x}".format(excp.invalid_address))

    def get_right_child(self):
        """Get the right child member."""

        if self.has_member("RightChild"):
            return self.RightChild

        elif self.has_member("Right"):
            return self.Right

        # this is for windows 8 and 10
        elif self.has_member("VadNode"):
            if self.VadNode.has_member("RightChild"):
                return self.VadNode.RightChild
            if self.VadNode.has_member("Right"):
                return self.VadNode.Right

        # also for windows 8 and 10
        elif self.has_member("Core"):
            if self.Core.has_member("VadNode"):
                if self.Core.VadNode.has_member("RightChild"):
                    return self.Core.VadNode.RightChild
                if self.Core.VadNode.has_member("Right"):
                    return self.Core.VadNode.Right

        raise AttributeError("Unable to find the right child member")

    def get_left_child(self):
        """Get the left child member."""

        if self.has_member("LeftChild"):
            return self.LeftChild

        elif self.has_member("Left"):
            return self.Left

        # this is for windows 8 and 10
        elif self.has_member("VadNode"):
            if self.VadNode.has_member("LeftChild"):
                return self.VadNode.LeftChild
            if self.VadNode.has_member("Left"):
                return self.VadNode.Left

        # also for windows 8 and 10
        elif self.has_member("Core"):
            if self.Core.has_member("VadNode"):
                if self.Core.VadNode.has_member("LeftChild"):
                    return self.Core.VadNode.LeftChild
                if self.Core.VadNode.has_member("Left"):
                    return self.Core.VadNode.Left

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


class MMVAD(MMVAD_SHORT):
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

        except exceptions.InvalidAddressException:
            pass

        return file_name


class EX_FAST_REF(objects.StructType):
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


class DEVICE_OBJECT(objects.StructType, pool.ExecutiveObject):
    """A class for kernel device objects."""

    def get_device_name(self) -> str:
        header = self.get_object_header()
        return header.NameInfo.Name.String  # type: ignore


class DRIVER_OBJECT(objects.StructType, pool.ExecutiveObject):
    """A class for kernel driver objects."""

    def get_driver_name(self) -> str:
        header = self.get_object_header()
        return header.NameInfo.Name.String  # type: ignore

    def is_valid(self) -> bool:
        """Determine if the object is valid."""
        return True


class OBJECT_SYMBOLIC_LINK(objects.StructType, pool.ExecutiveObject):
    """A class for kernel link objects."""

    def get_link_name(self) -> str:
        header = self.get_object_header()
        return header.NameInfo.Name.String  # type: ignore

    def is_valid(self) -> bool:
        """Determine if the object is valid."""
        return True

    def get_create_time(self):
        return conversion.wintime_to_datetime(self.CreationTime.QuadPart)


class FILE_OBJECT(objects.StructType, pool.ExecutiveObject):
    """A class for windows file objects."""

    def is_valid(self) -> bool:
        """Determine if the object is valid."""
        return self.FileName.Length > 0 and self._context.layers[self.FileName.Buffer.vol.native_layer_name].is_valid(
            self.FileName.Buffer)

    def file_name_with_device(self) -> Union[str, interfaces.renderers.BaseAbsentValue]:
        name = renderers.UnreadableValue()  # type: Union[str, interfaces.renderers.BaseAbsentValue]

        if self._context.layers[self.DeviceObject.vol.native_layer_name].is_valid(self.DeviceObject):
            try:
                name = "\\Device\\{}".format(self.DeviceObject.get_device_name())
            except ValueError:
                pass

        try:
            name += self.FileName.String
        except (TypeError, exceptions.InvalidAddressException):
            pass

        return name
  
    def access_string(self):
        ## Make a nicely formatted ACL string
        return (('R' if self.ReadAccess else '-') +
                ('W' if self.WriteAccess else '-') +
                ('D' if self.DeleteAccess else '-') +
                ('r' if self.SharedRead else '-') +
                ('w' if self.SharedWrite else '-') +
                ('d' if self.SharedDelete else '-'))

class KMUTANT(objects.StructType, pool.ExecutiveObject):
    """A class for windows mutant objects."""

    def is_valid(self) -> bool:
        """Determine if the object is valid."""
        return True

    def get_name(self) -> str:
        """Get the object's name from the object header."""
        header = self.get_object_header()
        return header.NameInfo.Name.String  # type: ignore


class ETHREAD(objects.StructType):
    """A class for executive thread objects."""

    def owning_process(self, kernel_layer: str = None) -> interfaces.objects.ObjectInterface:
        """Return the EPROCESS that owns this thread."""
        return self.ThreadsProcess.dereference(kernel_layer)

    def get_cross_thread_flags(self) -> str:
        dictCrossThreadFlags = {'PS_CROSS_THREAD_FLAGS_TERMINATED': 0,
                                'PS_CROSS_THREAD_FLAGS_DEADTHREAD': 1,
                                'PS_CROSS_THREAD_FLAGS_HIDEFROMDBG': 2,
                                'PS_CROSS_THREAD_FLAGS_IMPERSONATING': 3,
                                'PS_CROSS_THREAD_FLAGS_SYSTEM': 4,
                                'PS_CROSS_THREAD_FLAGS_HARD_ERRORS_DISABLED': 5,
                                'PS_CROSS_THREAD_FLAGS_BREAK_ON_TERMINATION': 6,
                                'PS_CROSS_THREAD_FLAGS_SKIP_CREATION_MSG': 7,
                                'PS_CROSS_THREAD_FLAGS_SKIP_TERMINATION_MSG': 8}
        
        flags = self.CrossThreadFlags
        stringCrossThreadFlags = ''
        for flag in dictCrossThreadFlags:
            if flags & 2**dictCrossThreadFlags[flag]:
                stringCrossThreadFlags += '{} '.format(flag)

        return stringCrossThreadFlags[:-1] if stringCrossThreadFlags else stringCrossThreadFlags


class UNICODE_STRING(objects.StructType):
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


class EPROCESS(generic.GenericIntelProcess, pool.ExecutiveObject):
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

            # check for all 0s besides the PCID entries
            if isinstance(self.Pcb.DirectoryTableBase, objects.Array):
                dtb = self.Pcb.DirectoryTableBase.cast("pointer")
            else:
                dtb = self.Pcb.DirectoryTableBase

            if dtb == 0:
                return False

            # check for all 0s besides the PCID entries
            if dtb & ~0xfff == 0:
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

    def get_peb(self) -> interfaces.objects.ObjectInterface:
        """Constructs a PEB object"""
        if constants.BANG not in self.vol.type_name:
            raise ValueError("Invalid symbol table name syntax (no {} found)".format(constants.BANG))

        # add_process_layer can raise InvalidAddressException.
        # if that happens, we let the exception propagate upwards
        proc_layer_name = self.add_process_layer()

        proc_layer = self._context.layers[proc_layer_name]
        if not proc_layer.is_valid(self.Peb):
            raise exceptions.InvalidAddressException(proc_layer_name, self.Peb,
                                                     "Invalid address at {:0x}".format(self.Peb))

        sym_table = self.vol.type_name.split(constants.BANG)[0]
        peb = self._context.object("{}{}_PEB".format(sym_table, constants.BANG),
                                   layer_name = proc_layer_name,
                                   offset = self.Peb)
        return peb

    def load_order_modules(self) -> Iterable[interfaces.objects.ObjectInterface]:
        """Generator for DLLs in the order that they were loaded."""

        try:
            peb = self.get_peb()
            for entry in peb.Ldr.InLoadOrderModuleList.to_list(
                    "{}{}_LDR_DATA_TABLE_ENTRY".format(self.get_symbol_table_name(), constants.BANG),
                    "InLoadOrderLinks"):
                yield entry
        except exceptions.InvalidAddressException:
            return

    def init_order_modules(self) -> Iterable[interfaces.objects.ObjectInterface]:
        """Generator for DLLs in the order that they were initialized"""

        try:
            peb = self.get_peb()
            for entry in peb.Ldr.InInitializationOrderModuleList.to_list(
                    "{}{}_LDR_DATA_TABLE_ENTRY".format(self.get_symbol_table_name(), constants.BANG),
                    "InInitializationOrderLinks"):
                yield entry
        except exceptions.InvalidAddressException:
            return

    def mem_order_modules(self) -> Iterable[interfaces.objects.ObjectInterface]:
        """Generator for DLLs in the order that they appear in memory"""

        try:
            peb = self.get_peb()
            for entry in peb.Ldr.InMemoryOrderModuleList.to_list(
                    "{}{}_LDR_DATA_TABLE_ENTRY".format(self.get_symbol_table_name(), constants.BANG),
                    "InMemoryOrderLinks"):
                yield entry
        except exceptions.InvalidAddressException:
            return

    def get_handle_count(self):
        try:
            if self.has_member("ObjectTable"):
                if self.ObjectTable.has_member("HandleCount"):
                    return self.ObjectTable.HandleCount

        except exceptions.InvalidAddressException:
            vollog.log(constants.LOGLEVEL_VVV,
                       "Cannot access _EPROCESS.ObjectTable.HandleCount at {0:#x}".format(self.vol.offset))

        return renderers.UnreadableValue()

    def get_session_id(self):
        try:
            if self.has_member("Session"):
                if self.Session == 0:
                    return renderers.NotApplicableValue()

                symbol_table_name = self.get_symbol_table_name()
                kvo = self._context.layers[self.vol.native_layer_name].config['kernel_virtual_offset']
                ntkrnlmp = self._context.module(symbol_table_name,
                                                layer_name = self.vol.native_layer_name,
                                                offset = kvo,
                                                native_layer_name = self.vol.native_layer_name)
                session = ntkrnlmp.object(object_type = "_MM_SESSION_SPACE", offset = self.Session, absolute = True)

                if session.has_member("SessionId"):
                    return session.SessionId

        except exceptions.InvalidAddressException:
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

    def environment_variables(self):
        """Generator for environment variables. 

        The PEB points to our env block - a series of null-terminated
        unicode strings. Each string cannot be more than 0x7FFF chars. 
        End of the list is a quad-null. 
        """
        context = self._context
        process_space = self.add_process_layer()

        try:
            block = self.get_peb().ProcessParameters.Environment
            try:
                block_size = self.get_peb().ProcessParameters.EnvironmentSize
            except AttributeError: # Windows XP
                block_size = self.get_peb().ProcessParameters.Length
            envars = context.layers[process_space].read(block, block_size).decode("utf-16-le", errors='replace').split('\x00')[:-1]
        except exceptions.InvalidAddressException:
            return renderers.UnreadableValue()

        for envar in envars:
            split_index = envar.find('=')
            env = envar[:split_index]
            var = envar[split_index+1:]

            # Exlude parse problem with some types of env
            if env and var:
                yield env, var


class LIST_ENTRY(objects.StructType, collections.abc.Iterable):
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

        trans_layer = self._context.layers[layer]

        try:
            trans_layer.is_valid(self.vol.offset)
            link = getattr(self, direction).dereference()
        except exceptions.InvalidAddressException:
            return

        if not sentinel:
            yield self._context.object(symbol_type,
                                       layer,
                                       offset = self.vol.offset - relative_offset,
                                       native_layer_name = layer or self.vol.native_layer_name)

        seen = {self.vol.offset}
        while link.vol.offset not in seen:
            obj_offset = link.vol.offset - relative_offset

            try:
                trans_layer.is_valid(obj_offset)
            except exceptions.InvalidAddressException:
                return

            obj = self._context.object(symbol_type,
                                       layer,
                                       offset = obj_offset,
                                       native_layer_name = layer or self.vol.native_layer_name)
            yield obj

            seen.add(link.vol.offset)

            try:
                link = getattr(link, direction).dereference()
            except exceptions.InvalidAddressException:
                return

    def __iter__(self) -> Iterator[interfaces.objects.ObjectInterface]:
        return self.to_list(self.vol.parent.vol.type_name, self.vol.member_name)


class TOKEN(objects.StructType):
    """A class for process etoken object."""

    def get_sids(self) -> Iterable[str]:
        """Yield a sid for the current token object."""

        if self.UserAndGroupCount < 0xFFFF:
            layer_name = self.vol.layer_name
            kvo = self._context.layers[layer_name].config["kernel_virtual_offset"]        
            symbol_table = self.get_symbol_table_name()
            ntkrnlmp = self._context.module(symbol_table,
                                            layer_name = layer_name,
                                            offset = kvo)
            UserAndGroups = ntkrnlmp.object(object_type="array",
                                            offset=self.UserAndGroups.dereference().vol.get("offset") - kvo,
                                            subtype = ntkrnlmp.get_type("_SID_AND_ATTRIBUTES"),
                                            count=self.UserAndGroupCount)
            for sid_and_attr in UserAndGroups:
                try:
                    sid = sid_and_attr.Sid.dereference().cast("_SID")
                     # catch invalid pointers (UserAndGroupCount is too high)
                    if sid is None:
                        return
                    # this mimics the windows API IsValidSid
                    if sid.Revision & 0xF != 1 or sid.SubAuthorityCount > 15:
                        return
                    id_auth = ""
                    for i in sid.IdentifierAuthority.Value:
                        id_auth = i
                    SubAuthority = ntkrnlmp.object(object_type="array",
                                                   offset=sid.SubAuthority.vol.offset - kvo,
                                                   subtype = ntkrnlmp.get_type("unsigned long"),
                                                   count= int(sid.SubAuthorityCount))
                    yield "S-" + "-".join(str(i) for i in (sid.Revision, id_auth) +
                                          tuple(SubAuthority))
                except exceptions.InvalidAddressException:
                    vollog.log(constants.LOGLEVEL_VVVV, "InvalidAddressException while parsing for token sid")


    def privileges(self):
        """Return a list of privileges for the current token object."""
        
        try:
            for priv_index in range(64):
                yield (priv_index,
                       bool(self.Privileges.Present & (2**priv_index)),
                       bool(self.Privileges.Enabled & (2**priv_index)),
                       bool(self.Privileges.EnabledByDefault & (2**priv_index)))
        except AttributeError: # Windows XP
            layer_name = self.vol.layer_name
            kvo = self._context.layers[layer_name].config["kernel_virtual_offset"]        
            symbol_table = self.get_symbol_table_name()
            ntkrnlmp = self._context.module(symbol_table,
                                            layer_name = layer_name,
                                            offset = kvo)
            if self.PrivilegeCount < 1024:
                # This is a pointer to an array of _LUID_AND_ATTRIBUTES
                for luid in self.Privileges.dereference().cast("array", count=self.PrivilegeCount,
                                                               subtype=ntkrnlmp.get_type("_LUID_AND_ATTRIBUTES")):
                    # The Attributes member is a flag 
                    enabled = luid.Attributes & 2 != 0
                    default = luid.Attributes & 1 != 0
                    yield luid.Luid.LowPart, True, enabled, default


class KTHREAD(objects.StructType):
    """A class for thread control block objects."""
        
    def get_state(self) -> str:
        dictState = {0:'Initialized', 1: 'Ready', 2: 'Running', 3: 'Standby', 4: 'Terminated',
                     5: 'Waiting', 6: 'Transition', 7: 'DeferredReady', 8: 'GateWait'}
        return dictState.get(self.State, renderers.NotApplicableValue())

    def get_wait_reason(self) -> str:
        dictWaitReason = {0: 'Executive', 1: 'FreePage', 2: 'PageIn', 3: 'PoolAllocation',
                          4: 'DelayExecution', 5: 'Suspended', 6: 'UserRequest', 7: 'WrExecutive',
                          8: 'WrFreePage', 9: 'WrPageIn', 10: 'WrPoolAllocation', 11: 'WrDelayExecution',
                          12: 'WrSuspended', 13: 'WrUserRequest', 14: 'WrEventPair', 15: 'WrQueue',
                          16: 'WrLpcReceive', 17: 'WrLpcReply', 18: 'WrVirtualMemory', 19: 'WrPageOut',
                          20: 'WrRendezvous', 21: 'Spare2', 22: 'Spare3', 23: 'Spare4', 24: 'Spare5',
                          25: 'Spare6', 26: 'WrKernel', 27: 'WrResource', 28: 'WrPushLock', 29: 'WrMutex',
                          30: 'WrQuantumEnd', 31: 'WrDispatchInt', 32: 'WrPreempted',33: 'WrYieldExecution', 34: 'WrFastMutex', 35: 'WrGuardedMutex',
                          36: 'WrRundown', 37: 'MaximumWaitReason'}
        return dictWaitReason.get(self.WaitReason, renderers.NotApplicableValue())
