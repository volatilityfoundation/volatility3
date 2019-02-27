# This file was contributed to the Volatility Framework Version 3.
# Copyright (C) 2018 Volatility Foundation.
#
# THE LICENSED WORK IS PROVIDED UNDER THE TERMS OF THE Volatility Contributors
# Public License V1.0("LICENSE") AS FIRST COMPLETED BY: Volatility Foundation,
# Inc. ANY USE, PUBLIC DISPLAY, PUBLIC PERFORMANCE, REPRODUCTION OR DISTRIBUTION
# OF, OR PREPARATION OF SUBSEQUENT WORKS, DERIVATIVE WORKS OR DERIVED WORKS BASED
# ON, THE LICENSED WORK CONSTITUTES RECIPIENT'S ACCEPTANCE OF THIS LICENSE AND ITS
# TERMS, WHETHER OR NOT SUCH RECIPIENT READS THE TERMS OF THE LICENSE. "LICENSED
# WORK,” “RECIPIENT" AND “DISTRIBUTOR" ARE DEFINED IN THE LICENSE. A COPY OF THE
# LICENSE IS LOCATED IN THE TEXT FILE ENTITLED "LICENSE.txt" ACCOMPANYING THE
# CONTENTS OF THIS FILE. IF A COPY OF THE LICENSE DOES NOT ACCOMPANY THIS FILE, A
# COPY OF THE LICENSE MAY ALSO BE OBTAINED AT THE FOLLOWING WEB SITE:
# https://www.volatilityfoundation.org/license/vcpl_v1.0
#
# Software distributed under the License is distributed on an "AS IS" basis,
# WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License for the
# specific language governing rights and limitations under the License.
#

import logging
from typing import List, Optional

import volatility.plugins.windows.pslist as pslist

import volatility.framework.interfaces.plugins as interfaces_plugins
from volatility.framework import constants, exceptions, renderers, interfaces
from volatility.framework.configuration import requirements
from volatility.framework.objects import utility
from volatility.framework.renderers import format_hints

vollog = logging.getLogger(__name__)

try:
    import capstone

    has_capstone = True
except ImportError:
    has_capstone = False


class Handles(interfaces_plugins.PluginInterface):
    """Lists process open handles"""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._sar_value = None
        self._type_map = None
        self._cookie = None
        self._level_mask = 7

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        # Since we're calling the plugin, make sure we have the plugin's requirements
        return [
            requirements.TranslationLayerRequirement(
                name = 'primary', description = 'Memory layer for the kernel', architectures = ["Intel32", "Intel64"]),
            requirements.SymbolTableRequirement(name = "nt_symbols", description = "Windows kernel symbols")
        ]

    def _decode_pointer(self, value, magic):
        """Windows encodes pointers to objects and decodes them on the fly
        before using them. This function mimics the decoding routine so we
        can generate the proper pointer values as well."""

        value = value & 0xFFFFFFFFFFFFFFF8
        value = value >> magic
        # if (value & (1 << 47)):
        #    value = value | 0xFFFF000000000000

        return value

    def _get_item(self, handle_table_entry, handle_value):
        """Given  a handle table entry (_HANDLE_TABLE_ENTRY) structure from
        a process' handle table, determine where the corresponding object's
        _OBJECT_HEADER can be found."""

        virtual = self.config["primary"]

        try:
            # before windows 7
            if not self.context.memory[virtual].is_valid(handle_table_entry.Object):
                return None
            fast_ref = handle_table_entry.Object.cast(self.config["nt_symbols"] + constants.BANG + "_EX_FAST_REF")
            object_header = fast_ref.dereference().cast(self.config["nt_symbols"] + constants.BANG + "_OBJECT_HEADER")
            object_header.GrantedAccess = handle_table_entry.GrantedAccess
        except AttributeError:
            # starting with windows 8
            if handle_table_entry.LowValue == 0:
                return None

            magic = self.find_sar_value()

            # is this the right thing to raise here?
            if magic == None:
                raise AttributeError("Unable to find the SAR value for decoding handle table pointers")

            offset = self._decode_pointer(handle_table_entry.LowValue, magic)
            # print("LowValue: {0:#x} Magic: {1:#x} Offset: {2:#x}".format(handle_table_entry.InfoTable, magic, offset))
            object_header = self.context.object(
                self.config["nt_symbols"] + constants.BANG + "_OBJECT_HEADER", virtual, offset = offset)
            object_header.GrantedAccess = handle_table_entry.GrantedAccessBits

        object_header.HandleValue = handle_value
        return object_header

    def find_sar_value(self):
        """Locate ObpCaptureHandleInformationEx if it exists in the
        sample. Once found, parse it for the SAR value that we need
        to decode pointers in the _HANDLE_TABLE_ENTRY which allows us
        to find the associated _OBJECT_HEADER."""

        if self._sar_value is None:

            if not has_capstone:
                return None

            virtual_layer_name = self.config['primary']
            kvo = self.context.memory[virtual_layer_name].config['kernel_virtual_offset']
            ntkrnlmp = self.context.module(self.config["nt_symbols"], layer_name = virtual_layer_name, offset = kvo)

            try:
                func_addr = ntkrnlmp.get_symbol("ObpCaptureHandleInformationEx").address
            except exceptions.SymbolError:
                return None

            data = self.context.memory.read(virtual_layer_name, kvo + func_addr, 0x200)
            if data == None:
                return None

            md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)

            for (address, size, mnemonic, op_str) in md.disasm_lite(data, kvo + func_addr):
                # print("{} {} {} {}".format(address, size, mnemonic, op_str))

                if mnemonic.startswith("sar"):
                    # if we don't want to parse op strings, we can disasm the
                    # single sar instruction again, but we use disasm_lite for speed
                    self._sar_value = int(op_str.split(",")[1].strip(), 16)
                    break

        return self._sar_value

    @classmethod
    def list_objects(cls, context: interfaces.context.ContextInterface, layer_name: str, symbol_table: str) -> dict:
        """List the executive object types (_OBJECT_TYPE) using the
        ObTypeIndexTable or ObpObjectTypes symbol (differs per OS).
        This method will be necessary for determining what type of
        object we have given an object header.

        Note: The object type index map was hard coded into profiles
        in vol2, but we generate it dynamically now."""

        type_map = {}

        kvo = context.memory[layer_name].config['kernel_virtual_offset']
        ntkrnlmp = context.module(symbol_table, layer_name = layer_name, offset = kvo)

        try:
            table_addr = ntkrnlmp.get_symbol("ObTypeIndexTable").address
        except exceptions.SymbolError:
            table_addr = ntkrnlmp.get_symbol("ObpObjectTypes").address

        ptrs = ntkrnlmp.object(
            type_name = "array", offset = kvo + table_addr, subtype = ntkrnlmp.get_type("pointer"), count = 100)

        for i, ptr in enumerate(ptrs):  #type: ignore
            # the first entry in the table is always null. break the
            # loop when we encounter the first null entry after that
            if i > 0 and ptr == 0:
                break
            objt = ptr.dereference().cast(symbol_table + constants.BANG + "_OBJECT_TYPE")

            try:
                type_name = objt.Name.String
            except exceptions.PagedInvalidAddressException:
                vollog.log(constants.LOGLEVEL_VVV,
                           "Cannot access _OBJECT_HEADER.Name at {0:#x}".format(objt.Name.vol.offset))
                continue

            type_map[i] = type_name

        return type_map

    @classmethod
    def find_cookie(cls, context: interfaces.context.ContextInterface, layer_name: str,
                    symbol_table: str) -> Optional[interfaces.objects.ObjectInterface]:
        """Find the ObHeaderCookie value (if it exists)"""

        try:
            offset = context.symbol_space.get_symbol(symbol_table + constants.BANG + "ObHeaderCookie").address
        except exceptions.SymbolError:
            return None

        kvo = context.memory[layer_name].config['kernel_virtual_offset']
        return context.object(symbol_table + constants.BANG + "unsigned int", layer_name, offset = kvo + offset)

    def _make_handle_array(self, offset, level, depth = 0):
        """Parse a process' handle table and yield valid handle table
        entries, going as deep into the table "levels" as necessary."""

        virtual = self.config["primary"]
        kvo = self.context.memory[virtual].config['kernel_virtual_offset']

        ntkrnlmp = self.context.module(self.config["nt_symbols"], layer_name = virtual, offset = kvo)

        if level > 0:
            subtype = ntkrnlmp.get_type("pointer")
            count = 0x1000 / subtype.size
        else:
            subtype = ntkrnlmp.get_type("_HANDLE_TABLE_ENTRY")
            count = 0x1000 / subtype.size

        if not self.context.memory[virtual].is_valid(offset):
            return

        table = ntkrnlmp.object(type_name = "array", offset = offset, subtype = subtype, count = int(count))

        layer_object = self.context.memory[virtual]
        masked_offset = (offset & layer_object.maximum_address)

        for entry in table:

            if level > 0:
                for x in self._make_handle_array(entry, level - 1, depth):
                    yield x
                depth += 1
            else:
                handle_multiplier = 4
                handle_level_base = depth * count * handle_multiplier

                handle_value = (
                    (entry.vol.offset - masked_offset) / (subtype.size / handle_multiplier)) + handle_level_base

                item = self._get_item(entry, handle_value)

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

        try:
            TableCode = handle_table.TableCode & ~self._level_mask
            table_levels = handle_table.TableCode & self._level_mask
        except exceptions.PagedInvalidAddressException:
            vollog.log(constants.LOGLEVEL_VVV, "Handle table parsing was aborted due to an invalid address exception")
            return

        for handle_table_entry in self._make_handle_array(TableCode, table_levels):
            yield handle_table_entry

    def _generator(self, procs):

        type_map = self.list_objects(
            context = self.context, layer_name = self.config["primary"], symbol_table = self.config["nt_symbols"])
        cookie = self.find_cookie(
            context = self.context, layer_name = self.config["primary"], symbol_table = self.config["nt_symbols"])

        for proc in procs:

            try:
                object_table = proc.ObjectTable
            except exceptions.PagedInvalidAddressException:
                vollog.log(constants.LOGLEVEL_VVV,
                           "Cannot access _EPROCESS.ObjectType at {0:#x}".format(proc.ObjectTable.vol.offset))
                continue

            process_name = utility.array_to_string(proc.ImageFileName)

            for entry in self.handles(object_table):
                try:
                    obj_type = entry.get_object_type(type_map, cookie)

                    if obj_type == None:
                        continue

                    if obj_type == "File":
                        item = entry.Body.cast(self.config["nt_symbols"] + constants.BANG + "_FILE_OBJECT")
                        obj_name = item.file_name_with_device()
                    elif obj_type == "Process":
                        item = entry.Body.cast(self.config["nt_symbols"] + constants.BANG + "_EPROCESS")
                        obj_name = "{} Pid {}".format(utility.array_to_string(proc.ImageFileName), item.UniqueProcessId)
                    elif obj_type == "Thread":
                        item = entry.Body.cast(self.config["nt_symbols"] + constants.BANG + "_ETHREAD")
                        obj_name = "Tid {} Pid {}".format(item.Cid.UniqueThread, item.Cid.UniqueProcess)
                    elif obj_type == "Key":
                        item = entry.Body.cast(self.config["nt_symbols"] + constants.BANG + "_CM_KEY_BODY")
                        obj_name = item.get_full_key_name()
                    else:
                        try:
                            obj_name = entry.NameInfo.Name.String
                        except exceptions.InvalidAddressException:
                            obj_name = ""

                except (exceptions.InvalidAddressException):
                    vollog.log(constants.LOGLEVEL_VVV,
                               "Cannot access _OBJECT_HEADER at {0:#x}".format(entry.vol.offset))
                    continue

                yield (0, (proc.UniqueProcessId,
                           process_name,
                           format_hints.Hex(entry.Body.vol.offset),
                           format_hints.Hex(entry.HandleValue),
                           obj_type,
                           format_hints.Hex(entry.GrantedAccess),
                           obj_name))

    def run(self):

        filter_func = pslist.PsList.create_filter([self.config.get('pid', None)])

        return renderers.TreeGrid([("PID", int), ("Process", str),
                                   ("Offset", format_hints.Hex),
                                   ("HandleValue", format_hints.Hex),
                                   ("Type", str),
                                   ("GrantedAccess", format_hints.Hex),
                                   ("Name", str)],
                                  self._generator(
                                      pslist.PsList.list_processes(
                                          self.context,
                                          self.config['primary'],
                                          self.config['nt_symbols'],
                                          filter_func = filter_func)))
