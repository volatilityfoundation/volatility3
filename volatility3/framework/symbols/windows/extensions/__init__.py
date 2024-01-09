# This file is Copyright 2020 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

import collections.abc
import contextlib
import datetime
import functools
import logging
import math
from typing import Generator, Iterable, Iterator, List, Optional, Tuple, Union

from volatility3.framework import (
    constants,
    exceptions,
    interfaces,
    objects,
    renderers,
    symbols,
)
from volatility3.framework.interfaces.objects import ObjectInterface
from volatility3.framework.layers import intel
from volatility3.framework.renderers import conversion
from volatility3.framework.symbols import generic
from volatility3.framework.symbols.windows.extensions import kdbg, pe, pool

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

    @functools.lru_cache(maxsize=None)
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
            bytesobj = self._context.object(
                symbol_table_name + constants.BANG + "bytes",
                layer_name=self.vol.layer_name,
                offset=vad_address,
                native_layer_name=self.vol.native_layer_name,
                length=4,
            )

            return bytesobj.decode()
        except exceptions.InvalidAddressException:
            return None
        except UnicodeDecodeError:
            return None

    def traverse(self, visited=None, depth=0):
        """Traverse the VAD tree, determining each underlying VAD node type by
        looking up the pool tag for the structure and then casting into a new
        object."""

        # TODO: this is an arbitrary limit chosen based on past observations
        if depth > 100:
            vollog.log(
                constants.LOGLEVEL_VVV, "Vad tree is too deep, something went wrong!"
            )
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
        elif tag is not None and tag.startswith("Vad"):
            target = "_MMVAD"
        elif depth == 0:
            # the root node at depth 0 is allowed to not have a tag
            # but we still want to continue and access its right & left child
            target = None
        else:
            # any node other than the root that doesn't have a recognized tag
            # is just garbage and we skip the node entirely
            vollog.log(
                constants.LOGLEVEL_VVV,
                f"Skipping VAD at {self.vol.offset} depth {depth} with tag {tag}",
            )
            return

        if target:
            vad_object = self.cast(target)
            yield vad_object

        try:
            for vad_node in (
                self.get_left_child().dereference().traverse(visited, depth + 1)
            ):
                yield vad_node
        except exceptions.InvalidAddressException as excp:
            vollog.log(
                constants.LOGLEVEL_VVV,
                f"Invalid address on LeftChild: {excp.invalid_address:#x}",
            )

        try:
            for vad_node in (
                self.get_right_child().dereference().traverse(visited, depth + 1)
            ):
                yield vad_node
        except exceptions.InvalidAddressException as excp:
            vollog.log(
                constants.LOGLEVEL_VVV,
                f"Invalid address on RightChild: {excp.invalid_address:#x}",
            )

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

    def get_start(self) -> int:
        """Get the VAD's starting virtual address. This is the first accessible byte in the range."""

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

    def get_end(self) -> int:
        """Get the VAD's ending virtual address. This is the last accessible byte in the range."""

        if self.has_member("EndingVpn"):
            if self.has_member("EndingVpnHigh"):
                return (((self.EndingVpn + 1) << 12) | (self.EndingVpnHigh << 44)) - 1
            else:
                return ((self.EndingVpn + 1) << 12) - 1

        elif self.has_member("Core"):
            if self.Core.has_member("EndingVpnHigh"):
                return (
                    ((self.Core.EndingVpn + 1) << 12) | (self.Core.EndingVpnHigh << 44)
                ) - 1
            else:
                return ((self.Core.EndingVpn + 1) << 12) - 1

        raise AttributeError("Unable to find the ending VPN member")

    def get_size(self) -> int:
        """Get the size of the VAD region. The OS ensures page granularity."""
        return (self.get_end() - self.get_start()) + 1

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

        if (
            self.has_member("u1")
            and self.u1.has_member("VadFlags1")
            and self.u1.VadFlags1.has_member("PrivateMemory")
        ):
            return self.u1.VadFlags1.PrivateMemory

        elif (
            self.has_member("u")
            and self.u.has_member("VadFlags")
            and self.u.VadFlags.has_member("PrivateMemory")
        ):
            return self.u.VadFlags.PrivateMemory

        elif self.has_member("Core"):
            if (
                self.Core.has_member("u1")
                and self.Core.u1.has_member("VadFlags1")
                and self.Core.u1.VadFlags1.has_member("PrivateMemory")
            ):
                return self.Core.u1.VadFlags1.PrivateMemory

            elif (
                self.Core.has_member("u")
                and self.Core.u.has_member("VadFlags")
                and self.Core.u.VadFlags.has_member("PrivateMemory")
            ):
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

        with contextlib.suppress(exceptions.InvalidAddressException):
            # this is for xp and 2003
            if self.has_member("ControlArea"):
                filename_obj = self.ControlArea.FilePointer.FileName

            # this is for vista through windows 7
            else:
                filename_obj = (
                    self.Subsection.ControlArea.FilePointer.dereference()
                    .cast("_FILE_OBJECT")
                    .FileName
                )

            if filename_obj.Length > 0:
                file_name = filename_obj.get_string()

        return file_name


class EX_FAST_REF(objects.StructType):
    """This is a standard Windows structure that stores a pointer to an object
    but also leverages the least significant bits to encode additional details.

    When dereferencing the pointer, we need to strip off the extra bits.
    """

    def dereference(self) -> interfaces.objects.ObjectInterface:
        if constants.BANG not in self.vol.type_name:
            raise ValueError(
                f"Invalid symbol table name syntax (no {constants.BANG} found)"
            )

        # the mask value is different on 32 and 64 bits
        symbol_table_name = self.vol.type_name.split(constants.BANG)[0]
        if not symbols.symbol_table_is_64bit(self._context, symbol_table_name):
            max_fast_ref = 7
        else:
            max_fast_ref = 15

        return self._context.object(
            symbol_table_name + constants.BANG + "pointer",
            layer_name=self.vol.layer_name,
            offset=self.Object & ~max_fast_ref,
            native_layer_name=self.vol.native_layer_name,
        )


class DEVICE_OBJECT(objects.StructType, pool.ExecutiveObject):
    """A class for kernel device objects."""

    def get_device_name(self) -> str:
        """Get device's name from the object header."""
        header = self.get_object_header()
        return header.NameInfo.Name.String  # type: ignore

    def get_attached_devices(self) -> Generator[ObjectInterface, None, None]:
        """Enumerate the attached device's objects"""
        device = self.AttachedDevice.dereference()
        while device:
            yield device
            device = device.AttachedDevice.dereference()


class DRIVER_OBJECT(objects.StructType, pool.ExecutiveObject):
    """A class for kernel driver objects."""

    def get_driver_name(self) -> str:
        """Get driver's name from the object header."""
        header = self.get_object_header()
        return header.NameInfo.Name.String  # type: ignore

    def get_devices(self) -> Generator[ObjectInterface, None, None]:
        """Enumerate the driver's device objects"""
        device = self.DeviceObject.dereference()
        while device:
            yield device
            device = device.NextDevice.dereference()

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
        return self.FileName.Length > 0 and self._context.layers[
            self.FileName.Buffer.vol.native_layer_name
        ].is_valid(self.FileName.Buffer)

    def file_name_with_device(self) -> Union[str, interfaces.renderers.BaseAbsentValue]:
        name: Union[
            str, interfaces.renderers.BaseAbsentValue
        ] = renderers.UnreadableValue()

        # this pointer needs to be checked against native_layer_name because the object may
        # be instantiated from a primary (virtual) layer or a memory (physical) layer.
        if self._context.layers[self.vol.native_layer_name].is_valid(self.DeviceObject):
            with contextlib.suppress(ValueError):
                name = f"\\Device\\{self.DeviceObject.get_device_name()}"

        with contextlib.suppress(TypeError, exceptions.InvalidAddressException):
            name += self.FileName.String

        return name

    def access_string(self):
        ## Make a nicely formatted ACL string
        return (
            ("R" if self.ReadAccess else "-")
            + ("W" if self.WriteAccess else "-")
            + ("D" if self.DeleteAccess else "-")
            + ("r" if self.SharedRead else "-")
            + ("w" if self.SharedWrite else "-")
            + ("d" if self.SharedDelete else "-")
        )


class KMUTANT(objects.StructType, pool.ExecutiveObject):
    """A class for windows mutant objects."""

    def is_valid(self) -> bool:
        """Determine if the object is valid."""
        return True

    def get_name(self) -> str:
        """Get the object's name from the object header."""
        header = self.get_object_header()
        return header.NameInfo.Name.String  # type: ignore


class ETHREAD(objects.StructType, pool.ExecutiveObject):
    """A class for executive thread objects."""

    def is_valid(self) -> bool:
        """Determine if the object is valid."""

        try:
            # validation by TID:
            if self.Cid.UniqueThread % 4 != 0:  # NT tids are divisible by 4
                return False

            # validation by PID of parent process:
            if self.Cid.UniqueProcess % 4 != 0:
                return False

            # validation by thread creation time:
            if (
                self.Cid.UniqueProcess != 4
            ):  # The System process (PID 4) has no create time
                ctime = self.get_create_time()
                if not isinstance(ctime, datetime.datetime):
                    return False

                if not (1998 < ctime.year < 2030):
                    return False

        except exceptions.InvalidAddressException:
            return False

        # passed all validations
        return True

    def get_create_time(self):
        # For Windows XPs
        if self.has_member("ThreadsProcess"):
            return conversion.wintime_to_datetime(self.CreateTime.QuadPart >> 3)
        return conversion.wintime_to_datetime(self.CreateTime.QuadPart)

    def get_exit_time(self):
        return conversion.wintime_to_datetime(self.ExitTime.QuadPart)

    def owning_process(self) -> interfaces.objects.ObjectInterface:
        """Return the EPROCESS that owns this thread."""

        # For Windows XPs
        if self.has_member("ThreadsProcess"):
            return self.ThreadsProcess.dereference().cast("_EPROCESS")
        # For Windows Vista and later versions
        elif self.has_member("Tcb") and self.Tcb.has_member("Process"):
            return self.Tcb.Process.dereference().cast("_EPROCESS")
        else:
            raise AttributeError("Unable to find the owning process of ethread")

    def get_cross_thread_flags(self) -> str:
        dictCrossThreadFlags = {
            "PS_CROSS_THREAD_FLAGS_TERMINATED": 0,
            "PS_CROSS_THREAD_FLAGS_DEADTHREAD": 1,
            "PS_CROSS_THREAD_FLAGS_HIDEFROMDBG": 2,
            "PS_CROSS_THREAD_FLAGS_IMPERSONATING": 3,
            "PS_CROSS_THREAD_FLAGS_SYSTEM": 4,
            "PS_CROSS_THREAD_FLAGS_HARD_ERRORS_DISABLED": 5,
            "PS_CROSS_THREAD_FLAGS_BREAK_ON_TERMINATION": 6,
            "PS_CROSS_THREAD_FLAGS_SKIP_CREATION_MSG": 7,
            "PS_CROSS_THREAD_FLAGS_SKIP_TERMINATION_MSG": 8,
        }

        flags = self.CrossThreadFlags
        stringCrossThreadFlags = ""
        for flag in dictCrossThreadFlags:
            if flags & 2 ** dictCrossThreadFlags[flag]:
                stringCrossThreadFlags += f"{flag} "

        return (
            stringCrossThreadFlags[:-1]
            if stringCrossThreadFlags
            else stringCrossThreadFlags
        )


class UNICODE_STRING(objects.StructType):
    """A class for Windows unicode string structures."""

    def get_string(self) -> interfaces.objects.ObjectInterface:
        # We explicitly do *not* catch errors here, we allow an exception to be thrown
        # (otherwise there's no way to determine anything went wrong)
        # It's up to the user of this method to catch exceptions

        # We manually construct an object rather than casting a dereferenced pointer in case
        # the buffer length is 0 and the pointer is a NULL pointer
        return self._context.object(
            self.vol.type_name.split(constants.BANG)[0] + constants.BANG + "string",
            layer_name=self.Buffer.vol.native_layer_name,
            offset=self.Buffer,
            max_length=self.Length,
            errors="replace",
            encoding="utf16",
        )

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
            if dtb & ~0xFFF == 0:
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
            raise TypeError(
                "Parent layer is not a translation layer, unable to construct process layer"
            )

        # Presumably for 64-bit systems, the DTB is defined as an array, rather than an unsigned long long
        dtb: int = 0
        if isinstance(self.Pcb.DirectoryTableBase, objects.Array):
            dtb = self.Pcb.DirectoryTableBase.cast("unsigned long long")
        else:
            dtb = self.Pcb.DirectoryTableBase
        dtb = dtb & ((1 << parent_layer.bits_per_register) - 1)

        if preferred_name is None:
            preferred_name = self.vol.layer_name + f"_Process{self.UniqueProcessId}"

        # Add the constructed layer and return the name
        return self._add_process_layer(
            self._context, dtb, config_prefix, preferred_name
        )

    def get_peb(self) -> interfaces.objects.ObjectInterface:
        """Constructs a PEB object"""
        if constants.BANG not in self.vol.type_name:
            raise ValueError(
                f"Invalid symbol table name syntax (no {constants.BANG} found)"
            )

        # add_process_layer can raise InvalidAddressException.
        # if that happens, we let the exception propagate upwards
        proc_layer_name = self.add_process_layer()

        proc_layer = self._context.layers[proc_layer_name]
        if not proc_layer.is_valid(self.Peb):
            raise exceptions.InvalidAddressException(
                proc_layer_name, self.Peb, f"Invalid Peb address at {self.Peb:0x}"
            )

        sym_table = self.get_symbol_table_name()
        peb = self._context.object(
            f"{sym_table}{constants.BANG}_PEB",
            layer_name=proc_layer_name,
            offset=self.Peb,
        )
        return peb

    def load_order_modules(self) -> Iterable[interfaces.objects.ObjectInterface]:
        """Generator for DLLs in the order that they were loaded."""

        try:
            peb = self.get_peb()
            for entry in peb.Ldr.InLoadOrderModuleList.to_list(
                f"{self.get_symbol_table_name()}{constants.BANG}_LDR_DATA_TABLE_ENTRY",
                "InLoadOrderLinks",
            ):
                yield entry
        except exceptions.InvalidAddressException:
            return

    def init_order_modules(self) -> Iterable[interfaces.objects.ObjectInterface]:
        """Generator for DLLs in the order that they were initialized"""

        try:
            peb = self.get_peb()
            for entry in peb.Ldr.InInitializationOrderModuleList.to_list(
                f"{self.get_symbol_table_name()}{constants.BANG}_LDR_DATA_TABLE_ENTRY",
                "InInitializationOrderLinks",
            ):
                yield entry
        except exceptions.InvalidAddressException:
            return

    def mem_order_modules(self) -> Iterable[interfaces.objects.ObjectInterface]:
        """Generator for DLLs in the order that they appear in memory"""

        try:
            peb = self.get_peb()
            for entry in peb.Ldr.InMemoryOrderModuleList.to_list(
                f"{self.get_symbol_table_name()}{constants.BANG}_LDR_DATA_TABLE_ENTRY",
                "InMemoryOrderLinks",
            ):
                yield entry
        except exceptions.InvalidAddressException:
            return

    def get_handle_count(self):
        try:
            if self.has_member("ObjectTable"):
                if self.ObjectTable.has_member("HandleCount"):
                    return self.ObjectTable.HandleCount

        except exceptions.InvalidAddressException:
            vollog.log(
                constants.LOGLEVEL_VVV,
                f"Cannot access _EPROCESS.ObjectTable.HandleCount at {self.vol.offset:#x}",
            )

        return renderers.UnreadableValue()

    def get_session_id(self):
        try:
            if self.has_member("Session"):
                if self.Session == 0:
                    return renderers.NotApplicableValue()

                symbol_table_name = self.get_symbol_table_name()
                kvo = self._context.layers[self.vol.native_layer_name].config[
                    "kernel_virtual_offset"
                ]
                ntkrnlmp = self._context.module(
                    symbol_table_name,
                    layer_name=self.vol.native_layer_name,
                    offset=kvo,
                    native_layer_name=self.vol.native_layer_name,
                )
                session = ntkrnlmp.object(
                    object_type="_MM_SESSION_SPACE", offset=self.Session, absolute=True
                )

                if session.has_member("SessionId"):
                    return session.SessionId

        except exceptions.InvalidAddressException:
            vollog.log(
                constants.LOGLEVEL_VVV,
                f"Cannot access _EPROCESS.Session.SessionId at {self.vol.offset:#x}",
            )

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

        if value:
            return True

        return False

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
            except AttributeError:  # Windows XP
                block_size = self.get_peb().ProcessParameters.Length
            envars = (
                context.layers[process_space]
                .read(block, block_size)
                .decode("utf-16-le", errors="replace")
                .split("\x00")[:-1]
            )
        except exceptions.InvalidAddressException:
            return  # Generation finished

        for envar in envars:
            split_index = envar.find("=")
            env = envar[:split_index]
            var = envar[split_index + 1 :]

            # Exclude parse problem with some types of env
            if env and var:
                yield env, var
        return  # Generation finished


class LIST_ENTRY(objects.StructType, collections.abc.Iterable):
    """A class for double-linked lists on Windows."""

    def to_list(
        self,
        symbol_type: str,
        member: str,
        forward: bool = True,
        sentinel: bool = True,
        layer: Optional[str] = None,
    ) -> Iterator[interfaces.objects.ObjectInterface]:
        """Returns an iterator of the entries in the list."""

        layer = layer or self.vol.layer_name

        relative_offset = self._context.symbol_space.get_type(
            symbol_type
        ).relative_child_offset(member)

        direction = "Blink"
        if forward:
            direction = "Flink"

        trans_layer = self._context.layers[layer]

        try:
            is_valid = trans_layer.is_valid(self.vol.offset)
            if not is_valid:
                return

            link = getattr(self, direction).dereference()
        except exceptions.InvalidAddressException:
            return

        if not sentinel:
            yield self._context.object(
                symbol_type,
                layer,
                offset=self.vol.offset - relative_offset,
                native_layer_name=layer or self.vol.native_layer_name,
            )

        seen = {self.vol.offset}
        while link.vol.offset not in seen:
            obj_offset = link.vol.offset - relative_offset

            if not trans_layer.is_valid(obj_offset):
                return

            obj = self._context.object(
                symbol_type,
                layer,
                offset=obj_offset,
                native_layer_name=layer or self.vol.native_layer_name,
            )
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
            ntkrnlmp = self._context.module(
                symbol_table, layer_name=layer_name, offset=kvo
            )
            UserAndGroups = ntkrnlmp.object(
                object_type="array",
                offset=self.UserAndGroups.dereference().vol.get("offset") - kvo,
                subtype=ntkrnlmp.get_type("_SID_AND_ATTRIBUTES"),
                count=self.UserAndGroupCount,
            )
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
                    SubAuthority = ntkrnlmp.object(
                        object_type="array",
                        offset=sid.SubAuthority.vol.offset - kvo,
                        subtype=ntkrnlmp.get_type("unsigned long"),
                        count=int(sid.SubAuthorityCount),
                    )
                    yield "S-" + "-".join(
                        str(i) for i in (sid.Revision, id_auth) + tuple(SubAuthority)
                    )
                except exceptions.InvalidAddressException:
                    vollog.log(
                        constants.LOGLEVEL_VVVV,
                        "InvalidAddressException while parsing for token sid",
                    )

    def privileges(self):
        """Return a list of privileges for the current token object."""

        try:
            for priv_index in range(64):
                yield (
                    priv_index,
                    bool(self.Privileges.Present & (2**priv_index)),
                    bool(self.Privileges.Enabled & (2**priv_index)),
                    bool(self.Privileges.EnabledByDefault & (2**priv_index)),
                )
        except AttributeError:  # Windows XP
            if self.PrivilegeCount < 1024:
                # This is a pointer to an array of _LUID_AND_ATTRIBUTES
                for luid in self.Privileges.dereference().cast(
                    "array",
                    count=self.PrivilegeCount,
                    subtype=self._context.symbol_space[
                        self.get_symbol_table_name()
                    ].get_type("_LUID_AND_ATTRIBUTES"),
                ):
                    # The Attributes member is a flag
                    enabled = luid.Attributes & 2 != 0
                    default = luid.Attributes & 1 != 0
                    yield luid.Luid.LowPart, True, enabled, default
            else:
                vollog.log(constants.LOGLEVEL_VVVV, "Broken Token Privileges.")


class KTHREAD(objects.StructType):
    """A class for thread control block objects."""

    def get_state(self) -> str:
        dictState = {
            0: "Initialized",
            1: "Ready",
            2: "Running",
            3: "Standby",
            4: "Terminated",
            5: "Waiting",
            6: "Transition",
            7: "DeferredReady",
            8: "GateWait",
        }
        return dictState.get(self.State, renderers.NotApplicableValue())

    def get_wait_reason(self) -> str:
        dictWaitReason = {
            0: "Executive",
            1: "FreePage",
            2: "PageIn",
            3: "PoolAllocation",
            4: "DelayExecution",
            5: "Suspended",
            6: "UserRequest",
            7: "WrExecutive",
            8: "WrFreePage",
            9: "WrPageIn",
            10: "WrPoolAllocation",
            11: "WrDelayExecution",
            12: "WrSuspended",
            13: "WrUserRequest",
            14: "WrEventPair",
            15: "WrQueue",
            16: "WrLpcReceive",
            17: "WrLpcReply",
            18: "WrVirtualMemory",
            19: "WrPageOut",
            20: "WrRendezvous",
            21: "Spare2",
            22: "Spare3",
            23: "Spare4",
            24: "Spare5",
            25: "Spare6",
            26: "WrKernel",
            27: "WrResource",
            28: "WrPushLock",
            29: "WrMutex",
            30: "WrQuantumEnd",
            31: "WrDispatchInt",
            32: "WrPreempted",
            33: "WrYieldExecution",
            34: "WrFastMutex",
            35: "WrGuardedMutex",
            36: "WrRundown",
            37: "MaximumWaitReason",
        }
        return dictWaitReason.get(self.WaitReason, renderers.NotApplicableValue())


class CONTROL_AREA(objects.StructType):
    """A class for _CONTROL_AREA structures"""

    PAGE_SIZE = 0x1000
    PAGE_MASK = PAGE_SIZE - 1

    def is_valid(self) -> bool:
        """Determine if the object is valid."""
        try:
            # The Segment.ControlArea should point back to this object
            if self.Segment.ControlArea != self.vol.offset:
                return False

            # The SizeOfSegment should match the total PTEs multiplied by a default page size
            if self.Segment.SizeOfSegment != (
                self.Segment.TotalNumberOfPtes * self.PAGE_SIZE
            ):
                return False

            # The first SubsectionBase should not be page aligned
            # subsection = self.get_subsection()
            # if subsection.SubsectionBase & self.PAGE_MASK == 0:
            #    return False
        except exceptions.InvalidAddressException:
            return False

        # True if everything else passes
        return True

    def get_subsection(self) -> interfaces.objects.ObjectInterface:
        """Get the Subsection object, which is found immediately after the _CONTROL_AREA."""

        return self._context.object(
            self.get_symbol_table_name() + constants.BANG + "_SUBSECTION",
            layer_name=self.vol.layer_name,
            offset=self.vol.offset + self.vol.size,
            native_layer_name=self.vol.native_layer_name,
        )

    def get_pte(self, offset: int) -> interfaces.objects.ObjectInterface:
        """Get a PTE object at the requested offset"""

        return self._context.object(
            self.get_symbol_table_name() + constants.BANG + "_MMPTE",
            layer_name=self.vol.layer_name,
            offset=offset,
            native_layer_name=self.vol.native_layer_name,
        )

    def get_available_pages(self) -> Iterable[Tuple[int, int, int]]:
        """Get the available pages that correspond to a cached file.

        The tuples generated are (physical_offset, file_offset, page_size).
        """
        symbol_table_name = self.get_symbol_table_name()
        mmpte_type = self._context.symbol_space.get_type(
            symbol_table_name + constants.BANG + "_MMPTE"
        )
        mmpte_size = mmpte_type.size
        subsection = self.get_subsection()
        is_64bit = symbols.symbol_table_is_64bit(self._context, symbol_table_name)
        is_pae = self._context.layers[self.vol.layer_name].metadata.get("pae", False)

        # This is a null-terminated single-linked list.
        while subsection != 0:
            try:
                if subsection.ControlArea != self.vol.offset:
                    break
            except exceptions.InvalidAddressException:
                break

            # The offset into the file is stored implicitly based on the PTE location within the Subsection.
            starting_sector = subsection.StartingSector
            subsection_offset = starting_sector * 0x200

            # Similar to the check in is_valid(), make sure the SubsectionBase is not page aligned.
            # if subsection.SubsectionBase & self.PAGE_MASK == 0:
            #    break

            ptecount = 0
            while ptecount < subsection.PtesInSubsection:
                pte_offset = subsection.SubsectionBase + (mmpte_size * ptecount)
                file_offset = subsection_offset + ptecount * 0x1000

                try:
                    mmpte = self.get_pte(pte_offset)
                except exceptions.InvalidAddressException:
                    ptecount += 1
                    continue

                # First we check if the entry is valid. If so, then we get the physical offset.
                # The valid entries are actually handled by the hardware.
                if mmpte.u.Hard.Valid == 1:
                    physoffset = mmpte.u.Hard.PageFrameNumber << 12
                    yield physoffset, file_offset, self.PAGE_SIZE

                elif mmpte.u.Soft.Prototype == 1:
                    if not is_64bit and not is_pae:
                        subsection_offset = (
                            mmpte.u.Subsect.SubsectionAddressHigh << 7
                        ) | (mmpte.u.Subsect.SubsectionAddressLow << 3)

                # If the entry is not a valid physical address then see if it is in transition.
                elif mmpte.u.Trans.Transition == 1:
                    # TODO: Fix appropriately in a future release.
                    # Currently just a temporary workaround to deal with custom bit flag
                    # in the PFN field for pages in transition state.
                    # See https://github.com/volatilityfoundation/volatility3/pull/475
                    physoffset = (mmpte.u.Trans.PageFrameNumber & ((1 << 33) - 1)) << 12

                    yield physoffset, file_offset, self.PAGE_SIZE

                # Go to the next PTE entry
                ptecount += 1

            # Go to the next Subsection in the single-linked list
            subsection = subsection.NextSubsection


class VACB(objects.StructType):
    """A class for _VACB structures"""

    FILEOFFSET_MASK = 0xFFFFFFFFFFFF0000

    def get_file_offset(self) -> int:
        # The FileOffset member of VACB is used to denote the offset within the file where the
        # view begins. Since all views are 256 KB in size, the bottom 16 bits are used to
        # store the number of references to the view.
        return self.Overlay.FileOffset.QuadPart & self.FILEOFFSET_MASK


class SHARED_CACHE_MAP(objects.StructType):
    """A class for _SHARED_CACHE_MAP structures"""

    VACB_BLOCK = 0x40000
    VACB_OFFSET_SHIFT = 18
    VACB_LEVEL_SHIFT = 7
    VACB_SIZE_OF_FIRST_LEVEL = 1 << (VACB_OFFSET_SHIFT + VACB_LEVEL_SHIFT)
    VACB_ARRAY = 0x80

    def is_valid(self) -> bool:
        """Determine if the object is valid."""

        if self.FileSize.QuadPart <= 0 or self.ValidDataLength.QuadPart <= 0:
            return False

        if self.SectionSize.QuadPart < 0 or (
            (self.FileSize.QuadPart < self.ValidDataLength.QuadPart)
            and (self.ValidDataLength.QuadPart != 0x7FFFFFFFFFFFFFFF)
        ):
            return False

        return True

    def process_index_array(
        self,
        array_pointer: interfaces.objects.ObjectInterface,
        level: int,
        limit: int,
        vacb_list: Optional[List] = None,
    ) -> List:
        """Recursively process the sparse multilevel VACB index array.

        :param array_pointer: The address of a possible index array
        :param level: The current level
        :param limit: The level where we abandon all hope. Ideally this is 7
        :param vacb_list: An array of collected VACBs
        :return: Collected VACBs
        """
        if vacb_list is None:
            vacb_list = []

        if level > limit:
            return []

        symbol_table_name = self.get_symbol_table_name()
        pointer_type = self._context.symbol_space.get_type(
            symbol_table_name + constants.BANG + "pointer"
        )

        # Create an array of 128 entries for the VACB index array
        vacb_array = self._context.object(
            object_type=symbol_table_name + constants.BANG + "array",
            layer_name=self.vol.layer_name,
            offset=array_pointer,
            count=self.VACB_ARRAY,
            subtype=pointer_type,
        )

        # Iterate through the entries
        for counter in range(0, self.VACB_ARRAY):
            # Check if the VACB entry is in use
            if not vacb_array[counter]:
                continue

            vacb_obj = (
                vacb_array[counter]
                .dereference()
                .cast(symbol_table_name + constants.BANG + "_VACB")
            )
            if vacb_obj.SharedCacheMap == self.vol.offset:
                self.save_vacb(vacb_obj, vacb_list)
            else:
                # Process the next level of the multi-level array
                vacb_list = self.process_index_array(
                    vacb_array[counter], level + 1, limit, vacb_list
                )
        return vacb_list

    def save_vacb(self, vacb_obj: interfaces.objects.ObjectInterface, vacb_list: List):
        data = (
            int(vacb_obj.BaseAddress),
            int(vacb_obj.get_file_offset()),
            self.VACB_BLOCK,
        )
        vacb_list.append(data)

    def get_available_pages(self) -> List:
        """Get the available pages that correspond to a cached file.

        The lists generated are (virtual_offset, file_offset, page_size).
        """
        vacb_list = []
        section_size = self.SectionSize.QuadPart

        # Determine the number of VACBs within the cache (nonpaged). each VACB
        # represents a 256-KB view in the system cache.
        full_blocks = section_size // self.VACB_BLOCK
        left_over = section_size % self.VACB_BLOCK

        # As an optimization, the shared cache map object contains a VACB index array of four entries.
        # The VACB index arrays are arrays of pointers to VACBs, that track which views of a given file
        # are mapped in the cache. For example, the first entry in the VACB index array refers to the first
        # 256 KB of the file. The InitialVacbs can describe a file up to 1 MB (4xVACB).
        iterval = 0
        while (iterval < full_blocks) and (full_blocks <= 4):
            vacb_obj = self.InitialVacbs[iterval]
            with contextlib.suppress(exceptions.InvalidAddressException):
                # Make sure that the SharedCacheMap member of the VACB points back to the parent object.
                if vacb_obj.SharedCacheMap == self.vol.offset:
                    self.save_vacb(vacb_obj, vacb_list)
            iterval += 1

        # We also have to account for the spill over data that is not found in the full blocks.
        # The first case to consider is when the spill over is still in InitialVacbs.
        if (left_over > 0) and (full_blocks < 4):
            vacb_obj = self.InitialVacbs[iterval]
            if vacb_obj.SharedCacheMap == self.vol.offset:
                self.save_vacb(vacb_obj, vacb_list)

        # If the file is larger than 1 MB, a separate VACB index array needs to be allocated.
        # This is based on how many 256 KB blocks would be required for the size of the file.
        # This newly allocated VACB index array is found through the Vacbs member of SHARED_CACHE_MAP.
        vacb_obj = self.Vacbs

        # Note: avoid calling is_valid() here, since self.Vacbs is a pointer to a pointer
        if not vacb_obj:
            return vacb_list

        # There are a number of instances where the initial value in InitialVacb will also be the fist
        # entry in Vacbs. Thus we ignore, since it was already processed. It is possible to just
        # process again as the file offset is specified for each VACB.
        if self.InitialVacbs[0].vol.offset == vacb_obj:
            return vacb_list

        # If the file is less than 32 MB than it can be found in a single level VACB index array.
        symbol_table_name = self.get_symbol_table_name()
        pointer_type = self._context.symbol_space.get_type(
            symbol_table_name + constants.BANG + "pointer"
        )
        size_of_pointer = pointer_type.size

        if not section_size > self.VACB_SIZE_OF_FIRST_LEVEL:
            array_head = vacb_obj
            for counter in range(0, full_blocks):
                vacb_entry = self._context.object(
                    symbol_table_name + constants.BANG + "pointer",
                    layer_name=self.vol.layer_name,
                    offset=array_head + (counter * size_of_pointer),
                )

                # If we find a zero entry, then we proceed to the next one. If the entry is zero,
                # then the view is not mapped and we skip. We do not pad because we use the
                # FileOffset to seek to the correct offset in the file.
                if not vacb_entry:
                    continue

                vacb = vacb_entry.dereference().cast(
                    symbol_table_name + constants.BANG + "_VACB"
                )
                if vacb.SharedCacheMap == self.vol.offset:
                    self.save_vacb(vacb, vacb_list)

            if left_over > 0:
                vacb_entry = self._context.object(
                    symbol_table_name + constants.BANG + "pointer",
                    layer_name=self.vol.layer_name,
                    offset=array_head + ((counter + 1) * size_of_pointer),
                )

                if not vacb_entry:
                    return vacb_list

                vacb = vacb_entry.dereference().cast(
                    symbol_table_name + constants.BANG + "_VACB"
                )
                if vacb.SharedCacheMap == self.vol.offset:
                    self.save_vacb(vacb, vacb_list)

            # The file is less than 32 MB, so we can stop processing.
            return vacb_list

        # If we get to this point, then we know that the SectionSize is greater than
        # VACB_SIZE_OF_FIRST_LEVEL (32 MB). Then we have a "sparse" multilevel index
        # array where each VACB index array is made up of 128 entries. We no
        # longer assume the data is sequential. (Log2 (32 MB) - 18)/7
        level_depth = math.ceil(math.log(section_size, 2))
        level_depth = (level_depth - self.VACB_OFFSET_SHIFT) / self.VACB_LEVEL_SHIFT
        level_depth = math.ceil(level_depth)
        limit_depth = level_depth

        if section_size > self.VACB_SIZE_OF_FIRST_LEVEL:
            # Create an array of 128 entries for the VACB index array.
            vacb_array = self._context.object(
                object_type=symbol_table_name + constants.BANG + "array",
                layer_name=self.vol.layer_name,
                offset=vacb_obj,
                count=self.VACB_ARRAY,
                subtype=pointer_type,
            )

            # Walk the array and if any entry points to the shared cache map object then we extract it.
            # Otherwise, if it is non-zero, then traverse to the next level.
            for counter in range(0, self.VACB_ARRAY):
                if not vacb_array[counter]:
                    continue

                vacb = (
                    vacb_array[counter]
                    .dereference()
                    .cast(symbol_table_name + constants.BANG + "_VACB")
                )
                if vacb.SharedCacheMap == self.vol.offset:
                    self.save_vacb(vacb, vacb_list)
                else:
                    # Process the next level of the multi-level array. We set the limit_depth to be
                    # the depth of the tree as determined from the size and we initialize the
                    # current level to 2.
                    vacb_list = self.process_index_array(
                        vacb_array[counter], 2, limit_depth, vacb_list
                    )

        return vacb_list
