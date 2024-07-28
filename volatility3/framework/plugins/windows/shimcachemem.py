# This file is Copyright 2020 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
import logging
import os
from datetime import datetime
from itertools import count
from typing import Iterator, List, Optional, Tuple

from volatility3.framework import constants, exceptions, interfaces, renderers, symbols
from volatility3.framework.configuration import requirements
from volatility3.framework.objects.utility import array_to_string
from volatility3.framework.renderers import format_hints
from volatility3.framework.symbols import intermed
from volatility3.framework.symbols.windows import versions
from volatility3.framework.symbols.windows.extensions import pe, shimcache
from volatility3.plugins import timeliner
from volatility3.plugins.windows import modules, pslist, vadinfo

# from volatility3.plugins.windows import pslist, vadinfo, modules

vollog = logging.getLogger(__name__)


class ShimcacheMem(interfaces.plugins.PluginInterface, timeliner.TimeLinerInterface):
    """Reads Shimcache entries from the ahcache.sys AVL tree"""

    _required_framework_version = (2, 0, 0)

    # These checks must be completed from newest -> oldest OS version.
    _win_version_file_map: List[Tuple[versions.OsDistinguisher, bool, str]] = [
        (versions.is_win10, True, "shimcache-win10-x64"),
        (versions.is_win10, False, "shimcache-win10-x86"),
        (versions.is_windows_8_or_later, True, "shimcache-win8-x64"),
        (versions.is_windows_8_or_later, False, "shimcache-win8-x86"),
        (versions.is_windows_7, True, "shimcache-win7-x64"),
        (versions.is_windows_7, False, "shimcache-win7-x86"),
        (versions.is_vista_or_later, True, "shimcache-vista-x64"),
        (versions.is_vista_or_later, False, "shimcache-vista-x86"),
        (versions.is_2003, False, "shimcache-2003-x86"),
        (versions.is_2003, True, "shimcache-2003-x64"),
        (versions.is_windows_xp_sp3, False, "shimcache-xp-sp3-x86"),
        (versions.is_windows_xp_sp2, False, "shimcache-xp-sp2-x86"),
        (versions.is_xp_or_2003, True, "shimcache-xp-2003-x64"),
        (versions.is_xp_or_2003, False, "shimcache-xp-2003-x86"),
    ]

    NT_KRNL_MODS = ["ntoskrnl.exe", "ntkrnlpa.exe", "ntkrnlmp.exe", "ntkrpamp.exe"]

    def generate_timeline(
        self,
    ) -> Iterator[Tuple[str, timeliner.TimeLinerType, datetime]]:
        for _, (_, last_modified, last_update, _, _, file_path) in self._generator():
            if isinstance(last_update, datetime):
                yield f"Shimcache: File {file_path} executed", timeliner.TimeLinerType.ACCESSED, last_update
            if isinstance(last_modified, datetime):
                yield f"Shimcache: File {file_path} modified", timeliner.TimeLinerType.MODIFIED, last_modified

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
                name="vadinfo", component=vadinfo.VadInfo, version=(2, 0, 0)
            ),
            requirements.VersionRequirement(
                name="modules", component=modules.Modules, version=(2, 0, 0)
            ),
        ]

    @staticmethod
    def create_shimcache_table(
        context: interfaces.context.ContextInterface,
        symbol_table: str,
        config_path: str,
    ) -> str:
        """Creates a shimcache symbol table

        Args:
            context: The context to retrieve required elements (layers, symbol tables) from
            symbol_table: The name of an existing symbol table containing the kernel symbols
            config_path: The configuration path within the context of the symbol table to create

        Returns:
            The name of the constructed shimcache table
        """
        native_types = context.symbol_space[symbol_table].natives
        is_64bit = symbols.symbol_table_is_64bit(context, symbol_table)
        table_mapping = {"nt_symbols": symbol_table}

        try:
            symbol_filename = next(
                filename
                for version_check, for_64bit, filename in ShimcacheMem._win_version_file_map
                if is_64bit == for_64bit
                and version_check(context=context, symbol_table=symbol_table)
            )
        except StopIteration:
            raise NotImplementedError("This version of Windows is not supported!")

        vollog.debug(f"Using shimcache table {symbol_filename}")

        return intermed.IntermediateSymbolTable.create(
            context,
            config_path,
            os.path.join("windows", "shimcache"),
            symbol_filename,
            class_types=shimcache.class_types,
            native_types=native_types,
            table_mapping=table_mapping,
        )

    @classmethod
    def find_shimcache_win_xp(
        cls,
        context: interfaces.context.ContextInterface,
        layer_name: str,
        kernel_symbol_table: str,
        shimcache_symbol_table: str,
    ) -> Iterator[shimcache.SHIM_CACHE_ENTRY]:
        """Attempts to find the shimcache in a Windows XP memory image

        :param context: The context to retrieve required elements (layers, symbol tables) from
        :param layer_name: The name of the memory layer on which to operate.
        :param kernel_symbol_table: The name of an existing symbol table containing the kernel symbols
        :param shimcache_symbol_table: The name of a symbol table containing the hand-crafted shimcache symbols
        """

        SHIM_NUM_ENTRIES_OFFSET = 0x8
        SHIM_MAX_ENTRIES = 0x60  # 96 max entries in XP shim cache
        SHIM_LRU_OFFSET = 0x10
        SHIM_HEADER_SIZE = 0x190
        SHIM_CACHE_ENTRY_SIZE = 0x228

        seen = set()

        for process in pslist.PsList.list_processes(
            context, layer_name, kernel_symbol_table
        ):
            pid = process.UniqueProcessId
            vollog.debug("checking process %d" % pid)
            for vad in vadinfo.VadInfo.list_vads(
                process, lambda x: x.get_tag() == b"Vad " and x.Protection == 4
            ):
                try:
                    proc_layer_name = process.add_process_layer()
                    proc_layer = context.layers[proc_layer_name]
                except exceptions.InvalidAddressException:
                    continue

                try:
                    if proc_layer.read(vad.get_start(), 4) != b"\xEF\xBE\xAD\xDE":
                        if pid == 624:
                            vollog.debug("VAD magic bytes don't match DEADBEEF")
                        continue
                except exceptions.InvalidAddressException:
                    continue

                num_entries = context.object(
                    shimcache_symbol_table + constants.BANG + "unsigned int",
                    proc_layer_name,
                    vad.get_start() + SHIM_NUM_ENTRIES_OFFSET,
                )

                if num_entries > SHIM_MAX_ENTRIES:
                    continue

                cache_idx_ptr = vad.get_start() + SHIM_LRU_OFFSET

                for _ in range(num_entries):
                    cache_idx_val = proc_layer.context.object(
                        shimcache_symbol_table + constants.BANG + "unsigned long",
                        proc_layer_name,
                        cache_idx_ptr,
                    )

                    cache_idx_ptr += 4

                    if cache_idx_val > SHIM_MAX_ENTRIES - 1:
                        continue

                    shim_entry_offset = (
                        vad.get_start()
                        + SHIM_HEADER_SIZE
                        + (SHIM_CACHE_ENTRY_SIZE * cache_idx_val)
                    )

                    if not proc_layer.is_valid(shim_entry_offset):
                        continue

                    physical_addr = proc_layer.translate(shim_entry_offset)

                    if physical_addr in seen:
                        continue
                    seen.add(physical_addr)

                    shim_entry = proc_layer.context.object(
                        shimcache_symbol_table + constants.BANG + "SHIM_CACHE_ENTRY",
                        proc_layer_name,
                        shim_entry_offset,
                    )
                    if not proc_layer.is_valid(shim_entry.vol.offset):
                        continue
                    if not shim_entry.is_valid():
                        continue

                    yield shim_entry

    @classmethod
    def find_shimcache_win_2k3_to_7(
        cls,
        context: interfaces.context.ContextInterface,
        config_path: str,
        kernel_layer_name: str,
        nt_symbol_table: str,
        shimcache_symbol_table: str,
    ) -> Iterator[shimcache.SHIM_CACHE_ENTRY]:
        """Implements the algorithm to search for the shim cache on Windows 2000
        (x64) through Windows 7 / 2008 R2. The algorithm consists of the following:

        1) Find the NT kernel module's .data and PAGE sections
        2) Iterate over every 4/8 bytes (depending on OS bitness) in the .data
           section and test for the following:
           a) offset represents a valid RTL_AVL_TABLE object
           b) RTL_AVL_TABLE is preceeded by an ERESOURCE object
           c) RTL_AVL_TABLE is followed by the beginning of the SHIM LRU list

        :param context: The context to retrieve required elements (layers, symbol tables) from
        :param layer_name: The name of the memory layer on which to operate.
        :param kernel_symbol_table: The name of an existing symbol table containing the kernel symbols
        :param shimcache_symbol_table: The name of a symbol table containing the hand-crafted shimcache symbols
        """

        data_sec = cls.get_module_section_range(
            context,
            config_path,
            kernel_layer_name,
            nt_symbol_table,
            cls.NT_KRNL_MODS,
            ".data",
        )
        mod_page = cls.get_module_section_range(
            context,
            config_path,
            kernel_layer_name,
            nt_symbol_table,
            cls.NT_KRNL_MODS,
            "PAGE",
        )

        # We require both in order to accurately handle AVL table
        if not (data_sec and mod_page):
            return None

        data_sec_offset, data_sec_size = data_sec
        mod_page_offset, mod_page_size = mod_page

        addr_size = 8 if symbols.symbol_table_is_64bit(context, nt_symbol_table) else 4

        shim_head = None
        for offset in range(
            data_sec_offset, data_sec_offset + data_sec_size, addr_size
        ):
            shim_head = cls.try_get_shim_head_at_offset(
                context,
                shimcache_symbol_table,
                nt_symbol_table,
                kernel_layer_name,
                mod_page_offset,
                mod_page_offset + mod_page_size,
                offset,
            )

            if shim_head:
                break

        if not shim_head:
            return

        for shim_entry in shim_head.ListEntry.to_list(
            shimcache_symbol_table + constants.BANG + "SHIM_CACHE_ENTRY", "ListEntry"
        ):
            yield shim_entry

    @classmethod
    def try_get_shim_head_at_offset(
        cls,
        context: interfaces.context.ContextInterface,
        symbol_table: str,
        kernel_symbol_table: str,
        layer_name: str,
        mod_page_start: int,
        mod_page_end: int,
        offset: int,
    ) -> Optional[shimcache.SHIM_CACHE_ENTRY]:
        """Attempts to construct a SHIM_CACHE_HEAD within a layer of the given context,
        using the provided offset within that layer, as well as the start and end offsets
        of the kernel module's `PAGE` section start and end offsets.

        If a number of validity checks are passed, this method will return the `SHIM_CACHE_HEAD`
        object. Otherwise, `None` is returned.
        """
        # print("checking RTL_AVL_TABLE at offset %s" % hex(offset))
        rtl_avl_table = context.object(
            symbol_table + constants.BANG + "_RTL_AVL_TABLE", layer_name, offset
        )
        if not rtl_avl_table.is_valid(mod_page_start, mod_page_end):
            return None

        vollog.debug(f"Candidate RTL_AVL_TABLE found at offset {hex(offset)}")

        ersrc_size = context.symbol_space.get_type(
            kernel_symbol_table + constants.BANG + "_ERESOURCE"
        ).size
        ersrc_alignment = (
            0x20
            if symbols.symbol_table_is_64bit(context, kernel_symbol_table)
            else 0x10
            # 0x20 if context.symbol_space.get_type("pointer").size == 8 else 0x10
        )
        vollog.debug(
            f"ERESOURCE size: {hex(ersrc_size)}, ERESOURCE alignment: {hex(ersrc_alignment)}"
        )

        eresource_rel_off = ersrc_size + ((offset - ersrc_size) % ersrc_alignment)
        eresource_offset = offset - eresource_rel_off

        vollog.debug("Constructing ERESOURCE at %s" % hex(eresource_offset))
        eresource = context.object(
            kernel_symbol_table + constants.BANG + "_ERESOURCE",
            layer_name,
            eresource_offset,
        )
        if not eresource.is_valid():
            vollog.debug("ERESOURCE Invalid")
            return None

        shim_head_offset = offset + rtl_avl_table.vol.size

        if not context.layers[layer_name].is_valid(shim_head_offset):
            return None

        shim_head = context.object(
            symbol_table + constants.BANG + "SHIM_CACHE_ENTRY",
            layer_name,
            shim_head_offset,
        )

        if not shim_head.is_valid():
            vollog.debug("shim head invalid")
            return None
        else:
            vollog.debug("returning shim head")
            return shim_head

    @classmethod
    def find_shimcache_win_8_or_later(
        cls,
        context: interfaces.context.ContextInterface,
        config_path: str,
        kernel_layer_name: str,
        nt_symbol_table: str,
        shimcache_symbol_table: str,
    ) -> Iterator[shimcache.SHIM_CACHE_ENTRY]:
        """Attempts to locate and yield shimcache entries from a Windows 8 or later memory image.

        :param context: The context to retrieve required elements (layers, symbol tables) from
        :param layer_name: The name of the memory layer on which to operate.
        :param kernel_symbol_table: The name of an existing symbol table containing the kernel symbols
        :param shimcache_symbol_table: The name of a symbol table containing the hand-crafted shimcache symbols
        """

        is_8_1_or_later = versions.is_windows_8_1_or_later(
            context, nt_symbol_table
        ) or versions.is_win10(context, nt_symbol_table)

        module_names = ["ahcache.sys"] if is_8_1_or_later else cls.NT_KRNL_MODS
        vollog.debug(f"Searching for modules {module_names}")

        data_sec = cls.get_module_section_range(
            context,
            config_path,
            kernel_layer_name,
            nt_symbol_table,
            module_names,
            ".data",
        )
        mod_page = cls.get_module_section_range(
            context,
            config_path,
            kernel_layer_name,
            nt_symbol_table,
            module_names,
            "PAGE",
        )

        if not (data_sec and mod_page):
            return None

        mod_page_offset, mod_page_size = mod_page
        data_sec_offset, data_sec_size = data_sec

        # iterate over ahcache kernel module's .data section in search of *two* SHIM handles
        shim_heads = []

        vollog.debug(f"PAGE offset: {hex(mod_page_offset)}")
        vollog.debug(f".data offset: {hex(data_sec_offset)}")

        handle_type = context.symbol_space.get_type(
            shimcache_symbol_table + constants.BANG + "SHIM_CACHE_HANDLE"
        )
        for offset in range(
            data_sec_offset,
            data_sec_offset + data_sec_size,
            8 if symbols.symbol_table_is_64bit(context, nt_symbol_table) else 4,
        ):
            vollog.debug(f"Building shim handle pointer at {hex(offset)}")
            shim_handle = context.object(
                object_type=shimcache_symbol_table + constants.BANG + "pointer",
                layer_name=kernel_layer_name,
                subtype=handle_type,
                offset=offset,
            )

            if shim_handle.is_valid(mod_page_offset, mod_page_offset + mod_page_size):
                if shim_handle.head is not None:
                    vollog.debug(
                        f"Found valid shim handle @ {hex(shim_handle.vol.offset)}"
                    )
                    shim_heads.append(shim_handle.head)
                if len(shim_heads) == 2:
                    break

        if len(shim_heads) != 2:
            vollog.debug("Failed to identify two valid SHIM_CACHE_HANDLE structures")
            return

        # On Windows 8 x64, the frist cache contains the shim cache
        # On Windows 8 x86, 8.1 x86/x64, and 10, the second cache contains the shim cache.
        if (
            not symbols.symbol_table_is_64bit(context, nt_symbol_table)
            and not is_8_1_or_later
        ):
            valid_head = shim_heads[1]
        elif not is_8_1_or_later:
            valid_head = shim_heads[0]
        else:
            valid_head = shim_heads[1]

        for shim_entry in valid_head.ListEntry.to_list(
            shimcache_symbol_table + constants.BANG + "SHIM_CACHE_ENTRY", "ListEntry"
        ):
            if shim_entry.is_valid():
                yield shim_entry

    def _generator(self):
        kernel = self.context.modules[self.config["kernel"]]

        shimcache_table_name = self.create_shimcache_table(
            self.context, kernel.symbol_table_name, self.config_path
        )

        c = count()

        if versions.is_windows_8_or_later(self._context, kernel.symbol_table_name):
            vollog.info("Finding shimcache entries for Windows 8.0+")
            entries = self.find_shimcache_win_8_or_later(
                self.context,
                self.config_path,
                kernel.layer_name,
                kernel.symbol_table_name,
                shimcache_table_name,
            )

        elif (
            versions.is_2003(self.context, kernel.symbol_table_name)
            or versions.is_vista_or_later(self.context, kernel.symbol_table_name)
            or versions.is_windows_7(self.context, kernel.symbol_table_name)
        ):
            vollog.info("Finding shimcache entries for Windows 2k3/Vista/7")
            entries = self.find_shimcache_win_2k3_to_7(
                self.context,
                self.config_path,
                kernel.layer_name,
                kernel.symbol_table_name,
                shimcache_table_name,
            )

        elif versions.is_windows_xp_sp2(
            self._context, kernel.symbol_table_name
        ) or versions.is_windows_xp_sp3(self.context, kernel.symbol_table_name):
            vollog.info("Finding shimcache entries for WinXP")
            entries = self.find_shimcache_win_xp(
                self._context,
                kernel.layer_name,
                kernel.symbol_table_name,
                shimcache_table_name,
            )
        else:
            vollog.warn("Cannot parse shimcache entries for this version of Windows")
            return

        for entry in entries:
            try:
                vollog.debug(f"SHIM_CACHE_ENTRY type: {entry.__class__}")
                shim_entry = (
                    entry.last_modified,
                    entry.last_update,
                    entry.exec_flag,
                    (
                        format_hints.Hex(entry.file_size)
                        if isinstance(entry.file_size, int)
                        else entry.file_size
                    ),
                    entry.file_path,
                )
            except exceptions.InvalidAddressException:
                continue

            yield (
                0,
                (next(c), *shim_entry),
            )

    def run(self):
        return renderers.TreeGrid(
            [
                ("Order", int),
                ("Last Modified", datetime),
                ("Last Update", datetime),
                ("Exec Flag", bool),
                ("File Size", format_hints.Hex),
                ("File Path", str),
            ],
            self._generator(),
        )

    @classmethod
    def get_module_section_range(
        cls,
        context: interfaces.context.ContextInterface,
        config_path: str,
        layer_name: str,
        symbol_table: str,
        module_list: List[str],
        section_name: str,
    ) -> Optional[Tuple[int, int]]:
        """Locates the size and offset of the first found module section
        specified by name from the list of modules.

        :param context: The context to operate on
        :param layer_name: The memory layer to read from
        :param module_list: A list of module names to search for the given section
        :param section_name: The name of the section to search for.

        :return: The offset and size of the module, if found; Otherwise, returns `None`
        """

        try:
            krnl_mod = next(
                module
                for module in modules.Modules.list_modules(
                    context, layer_name, symbol_table
                )
                if module.BaseDllName.String in module_list
            )
        except StopIteration:
            return None

        pe_table_name = intermed.IntermediateSymbolTable.create(
            context,
            interfaces.configuration.path_join(config_path, "pe"),
            "windows",
            "pe",
            class_types=pe.class_types,
        )

        # code taken from Win32KBase._section_chunks (win32_core.py)
        dos_header = context.object(
            pe_table_name + constants.BANG + "_IMAGE_DOS_HEADER",
            layer_name,
            offset=krnl_mod.DllBase,
        )

        if not dos_header:
            return None

        nt_header = dos_header.get_nt_header()

        try:
            section = next(
                sec
                for sec in nt_header.get_sections()
                if section_name.lower() == array_to_string(sec.Name).lower()
            )
        except StopIteration:
            return None

        section_offset = krnl_mod.DllBase + section.VirtualAddress
        section_size = section.Misc.VirtualSize

        return section_offset, section_size
