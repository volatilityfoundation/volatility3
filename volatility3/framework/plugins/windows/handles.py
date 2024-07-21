# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

import logging
from typing import List, Optional, Dict

from volatility3.framework import constants, exceptions, renderers, interfaces, symbols
from volatility3.framework.configuration import requirements
from volatility3.framework.objects import utility
from volatility3.framework.renderers import format_hints
from volatility3.plugins.windows import pslist, psscan

vollog = logging.getLogger(__name__)

try:
    import capstone

    has_capstone = True
except ImportError:
    has_capstone = False


class Handles(interfaces.plugins.PluginInterface):
    """Lists process open handles."""

    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 1)

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
            requirements.ModuleRequirement(
                name="kernel",
                description="Windows kernel",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.PluginRequirement(
                name="pslist", plugin=pslist.PsList, version=(2, 0, 0)
            ),
            requirements.VersionRequirement(
                name="psscan", component=psscan.PsScan, version=(1, 1, 0)
            ),
            requirements.ListRequirement(
                name="pid",
                element_type=int,
                description="Process IDs to include (all other processes are excluded)",
                optional=True,
            ),
            requirements.IntRequirement(
                name="offset",
                description="Process offset in the physical address space",
                optional=True,
            ),
        ]

    def _decode_pointer(self, value, magic):
        """Windows encodes pointers to objects and decodes them on the fly
        before using them.

        This function mimics the decoding routine so we can generate the
        proper pointer values as well.
        """

        value = value & 0xFFFFFFFFFFFFFFF8
        value = value >> magic
        # if (value & (1 << 47)):
        #    value = value | 0xFFFF000000000000

        return value

    def _get_item(self, handle_table_entry, handle_value):
        """Given  a handle table entry (_HANDLE_TABLE_ENTRY) structure from a
        process' handle table, determine where the corresponding object's
        _OBJECT_HEADER can be found."""

        kernel = self.context.modules[self.config["kernel"]]

        virtual = kernel.layer_name

        try:
            # before windows 7
            if not self.context.layers[virtual].is_valid(handle_table_entry.Object):
                return None
            fast_ref = handle_table_entry.Object.cast("_EX_FAST_REF")
            object_header = fast_ref.dereference().cast("_OBJECT_HEADER")
            object_header.GrantedAccess = handle_table_entry.GrantedAccess
        except AttributeError:
            # starting with windows 8
            is_64bit = symbols.symbol_table_is_64bit(
                self.context, kernel.symbol_table_name
            )

            if is_64bit:
                if handle_table_entry.LowValue == 0:
                    return None

                magic = self.find_sar_value()

                # is this the right thing to raise here?
                if magic is None:
                    if has_capstone:
                        raise AttributeError(
                            "Unable to find the SAR value for decoding handle table pointers"
                        )
                    else:
                        raise exceptions.MissingModuleException(
                            "capstone",
                            "Requires capstone to find the SAR value for decoding handle table pointers",
                        )

                offset = self._decode_pointer(handle_table_entry.LowValue, magic)
            else:
                if handle_table_entry.InfoTable == 0:
                    return None

                offset = handle_table_entry.InfoTable & ~7

            # print("LowValue: {0:#x} Magic: {1:#x} Offset: {2:#x}".format(handle_table_entry.InfoTable, magic, offset))
            object_header = self.context.object(
                kernel.symbol_table_name + constants.BANG + "_OBJECT_HEADER",
                virtual,
                offset=offset,
            )
            object_header.GrantedAccess = handle_table_entry.GrantedAccessBits

        object_header.HandleValue = handle_value
        return object_header

    def find_sar_value(self):
        """Locate ObpCaptureHandleInformationEx if it exists in the sample.

        Once found, parse it for the SAR value that we need to decode
        pointers in the _HANDLE_TABLE_ENTRY which allows us to find the
        associated _OBJECT_HEADER.
        """

        if self._sar_value is None:
            if not has_capstone:
                vollog.debug(
                    "capstone module is missing, unable to create disassembly of ObpCaptureHandleInformationEx"
                )
                return None
            kernel = self.context.modules[self.config["kernel"]]

            virtual_layer_name = kernel.layer_name
            kvo = self.context.layers[virtual_layer_name].config[
                "kernel_virtual_offset"
            ]
            ntkrnlmp = self.context.module(
                kernel.symbol_table_name, layer_name=virtual_layer_name, offset=kvo
            )

            try:
                func_addr = ntkrnlmp.get_symbol("ObpCaptureHandleInformationEx").address
            except exceptions.SymbolError:
                vollog.debug("Unable to locate ObpCaptureHandleInformationEx symbol")
                return None

            try:
                func_addr_to_read = kvo + func_addr
                num_bytes_to_read = 0x200
                vollog.debug(
                    f"ObpCaptureHandleInformationEx symbol located at {hex(func_addr_to_read)}"
                )
                data = self.context.layers.read(
                    virtual_layer_name, func_addr_to_read, num_bytes_to_read
                )
            except exceptions.InvalidAddressException:
                vollog.debug(
                    f"Failed to read {hex(num_bytes_to_read)} bytes at symbol {hex(func_addr_to_read)}"
                )
                return None

            md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)

            instruction_count = 0
            for address, size, mnemonic, op_str in md.disasm_lite(
                data, kvo + func_addr
            ):
                # print("{} {} {} {}".format(address, size, mnemonic, op_str))
                instruction_count += 1
                if mnemonic.startswith("sar"):
                    # if we don't want to parse op strings, we can disasm the
                    # single sar instruction again, but we use disasm_lite for speed
                    self._sar_value = int(op_str.split(",")[1].strip(), 16)
                    vollog.debug(
                        f"SAR located at {hex(address)} with value of {hex(self._sar_value)}"
                    )
                    break

            if self._sar_value is None:
                vollog.debug(
                    f"Failed to to locate SAR value having parsed {instruction_count} instructions"
                )

        return self._sar_value

    @classmethod
    def get_type_map(
        cls,
        context: interfaces.context.ContextInterface,
        layer_name: str,
        symbol_table: str,
    ) -> Dict[int, str]:
        """List the executive object types (_OBJECT_TYPE) using the
        ObTypeIndexTable or ObpObjectTypes symbol (differs per OS). This method
        will be necessary for determining what type of object we have given an
        object header.

        Note:
            The object type index map was hard coded into profiles in previous versions of volatility.
            It is now generated dynamically.

        Args:
            context: The context to retrieve required elements (layers, symbol tables) from
            layer_name: The name of the layer on which to operate
            symbol_table: The name of the table containing the kernel symbols

        Returns:
            A mapping of type indices to type names
        """

        type_map: Dict[int, str] = {}

        kvo = context.layers[layer_name].config["kernel_virtual_offset"]
        ntkrnlmp = context.module(symbol_table, layer_name=layer_name, offset=kvo)

        try:
            table_addr = ntkrnlmp.get_symbol("ObTypeIndexTable").address
        except exceptions.SymbolError:
            table_addr = ntkrnlmp.get_symbol("ObpObjectTypes").address

        trans_layer = context.layers[layer_name]

        if not trans_layer.is_valid(kvo + table_addr):
            return type_map

        ptrs = ntkrnlmp.object(
            object_type="array",
            offset=table_addr,
            subtype=ntkrnlmp.get_type("pointer"),
            count=100,
        )

        for i, ptr in enumerate(ptrs):  # type: ignore
            # the first entry in the table is always null. break the
            # loop when we encounter the first null entry after that
            if i > 0 and ptr == 0:
                break

            try:
                objt = ptr.dereference().cast(
                    symbol_table + constants.BANG + "_OBJECT_TYPE"
                )
                type_name = objt.Name.String
            except exceptions.InvalidAddressException:
                vollog.log(
                    constants.LOGLEVEL_VVV,
                    f"Cannot access _OBJECT_HEADER Name at {objt.vol.offset:#x}",
                )
                continue

            type_map[i] = type_name

        return type_map

    @classmethod
    def find_cookie(
        cls,
        context: interfaces.context.ContextInterface,
        layer_name: str,
        symbol_table: str,
    ) -> Optional[interfaces.objects.ObjectInterface]:
        """Find the ObHeaderCookie value (if it exists)"""

        try:
            offset = context.symbol_space.get_symbol(
                symbol_table + constants.BANG + "ObHeaderCookie"
            ).address
        except exceptions.SymbolError:
            return None

        kvo = context.layers[layer_name].config["kernel_virtual_offset"]
        return context.object(
            symbol_table + constants.BANG + "unsigned int",
            layer_name,
            offset=kvo + offset,
        )

    def _make_handle_array(self, offset, level, depth=0):
        """Parse a process' handle table and yield valid handle table entries,
        going as deep into the table "levels" as necessary."""

        kernel = self.context.modules[self.config["kernel"]]

        virtual = kernel.layer_name
        kvo = self.context.layers[virtual].config["kernel_virtual_offset"]

        ntkrnlmp = self.context.module(
            kernel.symbol_table_name, layer_name=virtual, offset=kvo
        )

        if level > 0:
            subtype = ntkrnlmp.get_type("pointer")
            count = 0x1000 / subtype.size
        else:
            subtype = ntkrnlmp.get_type("_HANDLE_TABLE_ENTRY")
            count = 0x1000 / subtype.size

        if not self.context.layers[virtual].is_valid(offset):
            return None

        table = ntkrnlmp.object(
            object_type="array",
            offset=offset,
            subtype=subtype,
            count=int(count),
            absolute=True,
        )

        layer_object = self.context.layers[virtual]
        masked_offset = offset & layer_object.maximum_address

        for entry in table:
            if level > 0:
                for x in self._make_handle_array(entry, level - 1, depth):
                    yield x
                depth += 1
            else:
                handle_multiplier = 4
                handle_level_base = depth * count * handle_multiplier

                handle_value = (
                    (entry.vol.offset - masked_offset)
                    / (subtype.size / handle_multiplier)
                ) + handle_level_base

                item = self._get_item(entry, handle_value)

                if item is None:
                    continue

                try:
                    if item.TypeIndex != 0x0:
                        yield item
                except AttributeError:
                    if item.Type.Name:
                        yield item
                except exceptions.InvalidAddressException:
                    continue

    def handles(self, handle_table):
        try:
            TableCode = handle_table.TableCode & ~self._level_mask
            table_levels = handle_table.TableCode & self._level_mask
        except exceptions.InvalidAddressException:
            vollog.log(
                constants.LOGLEVEL_VVV,
                "Handle table parsing was aborted due to an invalid address exception",
            )
            return None

        for handle_table_entry in self._make_handle_array(TableCode, table_levels):
            yield handle_table_entry

    def _generator(self, procs):
        kernel = self.context.modules[self.config["kernel"]]

        type_map = self.get_type_map(
            context=self.context,
            layer_name=kernel.layer_name,
            symbol_table=kernel.symbol_table_name,
        )

        cookie = self.find_cookie(
            context=self.context,
            layer_name=kernel.layer_name,
            symbol_table=kernel.symbol_table_name,
        )

        for proc in procs:
            try:
                object_table = proc.ObjectTable
            except exceptions.InvalidAddressException:
                vollog.log(
                    constants.LOGLEVEL_VVV,
                    f"Cannot access _EPROCESS.ObjectType at {proc.vol.offset:#x}",
                )
                continue

            process_name = utility.array_to_string(proc.ImageFileName)

            for entry in self.handles(object_table):
                try:
                    obj_type = entry.get_object_type(type_map, cookie)
                    if obj_type is None:
                        continue
                    if obj_type == "File":
                        item = entry.Body.cast("_FILE_OBJECT")
                        obj_name = item.file_name_with_device()
                    elif obj_type == "Process":
                        item = entry.Body.cast("_EPROCESS")
                        obj_name = f"{utility.array_to_string(item.ImageFileName)} Pid {item.UniqueProcessId}"
                    elif obj_type == "Thread":
                        item = entry.Body.cast("_ETHREAD")
                        obj_name = (
                            f"Tid {item.Cid.UniqueThread} Pid {item.Cid.UniqueProcess}"
                        )
                    elif obj_type == "Key":
                        item = entry.Body.cast("_CM_KEY_BODY")
                        obj_name = item.get_full_key_name()
                    else:
                        try:
                            obj_name = entry.NameInfo.Name.String
                        except (ValueError, exceptions.InvalidAddressException):
                            obj_name = ""

                except exceptions.InvalidAddressException:
                    vollog.log(
                        constants.LOGLEVEL_VVV,
                        f"Cannot access _OBJECT_HEADER at {entry.vol.offset:#x}",
                    )
                    continue

                yield (
                    0,
                    (
                        proc.UniqueProcessId,
                        process_name,
                        format_hints.Hex(entry.Body.vol.offset),
                        format_hints.Hex(entry.HandleValue),
                        obj_type,
                        format_hints.Hex(entry.GrantedAccess),
                        obj_name,
                    ),
                )

    def run(self):
        filter_func = pslist.PsList.create_pid_filter(self.config.get("pid", None))
        kernel = self.context.modules[self.config["kernel"]]

        if self.config["offset"]:
            procs = psscan.PsScan.scan_processes(
                self.context,
                kernel.layer_name,
                kernel.symbol_table_name,
                filter_func=psscan.PsScan.create_offset_filter(
                    self.context,
                    kernel.layer_name,
                    self.config["offset"],
                ),
            )
        else:
            procs = pslist.PsList.list_processes(
                context=self.context,
                layer_name=kernel.layer_name,
                symbol_table=kernel.symbol_table_name,
                filter_func=filter_func,
            )

        return renderers.TreeGrid(
            [
                ("PID", int),
                ("Process", str),
                ("Offset", format_hints.Hex),
                ("HandleValue", format_hints.Hex),
                ("Type", str),
                ("GrantedAccess", format_hints.Hex),
                ("Name", str),
            ],
            self._generator(procs=procs),
        )
