# This file is Copyright 2024 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0

import copy
import io
import logging
import ntpath

from typing import Dict, Tuple, Optional, List, Generator, Union, Callable

import pefile

from volatility3.framework import interfaces, exceptions
from volatility3.framework import renderers, constants
from volatility3.framework.configuration import requirements
from volatility3.framework.renderers import format_hints
from volatility3.framework.symbols import intermed
from volatility3.framework.symbols.windows import pdbutil
from volatility3.framework.symbols.windows.extensions import pe
from volatility3.plugins.windows import pslist, modules
from volatility3.framework.constants.windows import KERNEL_MODULE_NAMES

vollog = logging.getLogger(__name__)

# keys for specifying wanted names and/or addresses
# used for consistent access between the API and plugins
wanted_names_identifier = "names"
wanted_addresses_identifier = "addresses"

# how wanted modules/symbols are specified, such as:
# {"ntdll.dll" : {wanted_addresses : [42, 43, 43]}}
# {"ntdll.dll" : {wanted_names : ["NtCreateThread"]}}
filter_module_info = Union[Dict[str, List[str]], Dict[str, List[int]]]
filter_modules_type = Dict[str, filter_module_info]

# holds resolved symbols
# {"ntdll.dll": [("Bob", 123), ("Alice", 456)]}
found_symbols_module = List[Tuple[str, int]]
found_symbols_type = Dict[str, found_symbols_module]

# used to hold informatin about a range (VAD or kernel module)
# (start address, size, file path)
range_type = Tuple[int, int, str]
ranges_type = List[range_type]

# collected_modules are modules and their symbols found when walking vads or kernel modules
# Tuple of (process or kernel layer name, range start, range size)
collected_module_instance = Tuple[str, int, int]
collected_modules_info = List[collected_module_instance]
collected_modules_type = Dict[str, collected_modules_info]

PESymbolFinders = Union[interfaces.context.ModuleInterface, pefile.ExportDirData]


class PESymbolFinder:
    """
    Interface for PE symbol finding classes
    This interface provides a standard way for the calling code to
    lookup symbols by name or address
    """

    cached_str_dict = Dict[str, Optional[str]]

    cached_int_dict = Dict[str, Optional[int]]

    cached_value = Union[int, str, None]
    cached_module_lists = Union[Dict[str, List[str]], Dict[str, List[int]]]
    cached_value_dict = Dict[str, cached_module_lists]

    def __init__(
        self,
        layer_name: str,
        mod_name: str,
        module_start: int,
        symbol_module: PESymbolFinders,
    ):
        self._layer_name = layer_name
        self._mod_name = mod_name
        self._module_start = module_start
        self._symbol_module = symbol_module

        self._address_cache: PESymbolFinder.cached_int_dict = {}
        self._name_cache: PESymbolFinder.cached_str_dict = {}

    def _get_cache_key(self, value: cached_value) -> str:
        """
        Maintain a cache for symbol lookups to avoid re-walking of PDB symbols or export tables
        within the same module for the same address in the same layer

        Args:
            value: The value (address or name) being cached

        Returns:
            str: The constructed cache key that includes the layer and module name
        """
        return f"{self._layer_name}|{self._mod_name}|{value}"

    def get_name_for_address(self, address: int) -> Optional[str]:
        """
        Returns the name for the given address within the particular layer and module

        Args:
            address: the address to resolve within the module

        Returns:
            str: the name of the symbol, if found
        """
        cached_key = self._get_cache_key(address)
        if cached_key not in self._name_cache:
            name = self._do_get_name(address)
            self._name_cache[cached_key] = name

        return self._name_cache[cached_key]

    def get_address_for_name(self, name: str) -> Optional[int]:
        """
        Returns the name for the given address within the particular layer and module

        Args:
            str: the name of the symbol to resolve

        Returns:
            address: the address of the symbol, if found
        """
        cached_key = self._get_cache_key(name)
        if cached_key not in self._address_cache:
            address = self._do_get_address(name)
            self._address_cache[cached_key] = address

        return self._address_cache[cached_key]

    def _do_get_name(self, address: int) -> Optional[str]:
        """
        Returns the name for the given address within the particular layer and module.
        This method must be overwritten by sub classes.

        Args:
            address: the address to resolve within the module

        Returns:
            str: the name of the symbol, if found
        """
        raise NotImplementedError("_do_get_name must be overwritten")

    def _do_get_address(self, name: str) -> Optional[int]:
        """
        Returns the name for the given address within the particular layer and module
        This method must be overwritten by sub classes.

        Args:
            str: the name of the symbol to resolve

        Returns:
            address: the address of the symbol, if found
        """
        raise NotImplementedError("_do_get_address must be overwritten")


class PDBSymbolFinder(PESymbolFinder):
    """
    PESymbolFinder implementation for  PDB modules
    """

    def _do_get_address(self, name: str) -> Optional[int]:
        """
        _do_get_address implementation for PDBSymbolFinder

        Args:
            str: the name of the symbol to resolve

        Returns:
            address: the address of the symbol, if found
        """
        try:
            return self._symbol_module.get_absolute_symbol_address(name)
        except exceptions.SymbolError:
            return None

    def _do_get_name(self, address: int) -> Optional[str]:
        """
        _do_get_name  implementation for PDBSymbolFinder

        Args:
            address: the address to resolve within the module

        Returns:
            str: the name of the symbol, if found
        """
        try:
            name = self._symbol_module.get_symbols_by_absolute_location(address)[0]
            return name.split(constants.BANG)[1]
        except (exceptions.SymbolError, IndexError):
            return None


class ExportSymbolFinder(PESymbolFinder):
    """
    PESymbolFinder implementation for  PDB modules
    """

    def _get_name(self, export: pefile.ExportData) -> Optional[str]:
        # AttributeError throws on empty or ordinal-only exports
        try:
            return export.name.decode("ascii")
        except AttributeError:
            return None

    def _do_get_name(self, address: int) -> Optional[str]:
        """
        _do_get_name  implementation for ExportSymbolFinder

        Args:
            address: the address to resolve within the module

        Returns:
            str: the name of the symbol, if found
        """
        for export in self._symbol_module:
            if export.address + self._module_start == address:
                return self._get_name(export)

        return None

    def _do_get_address(self, name: str) -> Optional[int]:
        """
        _do_get_address implementation for ExportSymbolFinder
        Args:
            str: the name of the symbol to resolve

        Returns:
            address: the address of the symbol, if found
        """

        for export in self._symbol_module:
            sym_name = self._get_name(export)
            if sym_name and sym_name == name:
                return self._module_start + export.address

        return None


class PESymbols(interfaces.plugins.PluginInterface):
    """Prints symbols in PE files in process and kernel memory"""

    _required_framework_version = (2, 7, 0)

    _version = (1, 0, 0)

    # used for special handling of the kernel PDB file. See later notes
    os_module_name = "ntoskrnl.exe"

    @classmethod
    def get_requirements(cls) -> List:
        # Since we're calling the plugin, make sure we have the plugin's requirements
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Windows kernel",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.VersionRequirement(
                name="pslist", component=pslist.PsList, version=(2, 0, 0)
            ),
            requirements.VersionRequirement(
                name="modules", component=modules.Modules, version=(2, 0, 0)
            ),
            requirements.VersionRequirement(
                name="pdbutil", component=pdbutil.PDBUtility, version=(1, 0, 0)
            ),
            requirements.ChoiceRequirement(
                name="source",
                description="Where to resolve symbols.",
                choices=["kernel", "processes"],
                optional=False,
            ),
            requirements.StringRequirement(
                name="module",
                description='Module in which to resolve symbols. Use "ntoskrnl.exe" to resolve in the base kernel executable.',
                optional=False,
            ),
            requirements.ListRequirement(
                name="symbols",
                element_type=str,
                description="Symbol name to resolve",
                optional=True,
            ),
            requirements.ListRequirement(
                name="addresses",
                element_type=int,
                description="Address of symbol to resolve",
                optional=True,
            ),
        ]

    @staticmethod
    def _get_pefile_obj(
        context: interfaces.context.ContextInterface,
        pe_table_name: str,
        layer_name: str,
        base_address: int,
    ) -> Optional[pefile.PE]:
        """
        Attempts to pefile object from the bytes of the PE file

        Args:
            pe_table_name: name of the pe types table
            layer_name: name of the process layer
            base_address: base address of the module

        Returns:
            the constructed pefile object
        """
        pe_data = io.BytesIO()

        try:
            dos_header = context.object(
                pe_table_name + constants.BANG + "_IMAGE_DOS_HEADER",
                offset=base_address,
                layer_name=layer_name,
            )

            for offset, data in dos_header.reconstruct():
                pe_data.seek(offset)
                pe_data.write(data)

            pe_ret = pefile.PE(data=pe_data.getvalue(), fast_load=True)

        except exceptions.InvalidAddressException:
            pe_ret = None

        return pe_ret

    @staticmethod
    def range_info_for_address(
        ranges: ranges_type, address: int
    ) -> Optional[range_type]:
        """
        Helper for getting the range information for an address.
        Finds the range holding the `address` parameter

        Args:
            address: the address to find the range for

        Returns:
            Tuple[int, int, str]: The starting address, size, and file path of the range

        """
        for start, size, filepath in ranges:
            if start <= address < start + size:
                return start, size, filepath

        return None

    @staticmethod
    def filepath_for_address(ranges: ranges_type, address: int) -> Optional[str]:
        """
        Helper to get the file path for an address

        Args:
            ranges: The set of VADs with mapped files to find the address
            address: The address to find inside of the VADs set

        Returns:
            str: The full path of the file, if found and present
        """
        info = PESymbols.range_info_for_address(ranges, address)
        if info:
            return info[2]

        return None

    @staticmethod
    def filename_for_path(filepath: str) -> str:
        """
        Consistent way to get the filename regardless of platform

        Args:
            str: the file path from `filepath_for_address`

        Returns:
            str: the bsae file name of the full path
        """
        return ntpath.basename(filepath).lower()

    @staticmethod
    def addresses_for_process_symbols(
        context: interfaces.context.ContextInterface,
        config_path: str,
        layer_name: str,
        symbol_table_name: str,
        symbols: filter_modules_type,
    ) -> found_symbols_type:
        """
        Used to easily resolve the  addresses of names inside of modules.

        See the usage of this function for system call resolution in  unhooked_system_calls.py
        for an easy to understand example.

        Args:
            symbols: The dictionary of symbols requested by the caller

        Returns:
            found_symbols_type: The dictionary of symbols that were resolved
        """
        collected_modules = PESymbols.get_process_modules(
            context, layer_name, symbol_table_name, symbols
        )

        found_symbols, missing_symbols = PESymbols.find_symbols(
            context, config_path, symbols, collected_modules
        )

        for mod_name, unresolved_symbols in missing_symbols.items():
            for symbol in unresolved_symbols:
                vollog.debug(f"Unable to resolve symbol {symbol} in module {mod_name}")

        return found_symbols

    @staticmethod
    def path_and_symbol_for_address(
        context: interfaces.context.ContextInterface,
        config_path: str,
        collected_modules: collected_modules_type,
        ranges: ranges_type,
        address: int,
    ) -> Tuple[str, str]:
        """
        Method for plugins to determine the file path and symbol name for a given address

        See debugregisters.py for an example of how this function is used along with get_vads_for_process_cache
        for resolving symbols in processes.

        Args:
            collected_modules: return value from `get_kernel_modules` or `get_process_modules`
            ranges: the memory ranges to examine in this layer.
            address: address to resolve to its symbol name
        Returns:
            Tuple[str|renderers.NotApplicableValue|renderers.NotAvailableValue, str|renderers.NotApplicableValue|renderers.NotAvailableValue]
        """

        if not address:
            return renderers.NotApplicableValue(), renderers.NotApplicableValue()

        filepath = PESymbols.filepath_for_address(ranges, address)

        if not filepath:
            return renderers.NotAvailableValue(), renderers.NotAvailableValue()

        filename = PESymbols.filename_for_path(filepath).lower()

        # setup to resolve the address
        filter_module: filter_modules_type = {
            filename: {wanted_addresses_identifier: [address]}
        }

        found_symbols, _missing_msybols = PESymbols.find_symbols(
            context, config_path, filter_module, collected_modules
        )

        if not found_symbols or filename not in found_symbols:
            return renderers.NotAvailableValue(), renderers.NotAvailableValue()

        return filepath, found_symbols[filename][0][0]

    @staticmethod
    def _get_exported_symbols(
        context: interfaces.context.ContextInterface,
        pe_table_name: str,
        mod_name: str,
        module_info: collected_module_instance,
    ) -> Optional[ExportSymbolFinder]:
        """
        Attempts to locate symbols based on export analysis

        Args:
            mod_name: lower case name of the module to resolve symbols in
            module_info: (layer_name, module_start, module_size) of the module to examine

        Returns:
            Optional[ExportSymbolFinder]: If the export table can be resolved, then the ExportSymbolFinder
            instance for it
        """

        layer_name = module_info[0]
        module_start = module_info[1]

        # we need a valid PE with an export table
        pe_module = PESymbols._get_pefile_obj(
            context, pe_table_name, layer_name, module_start
        )
        if not pe_module:
            return None

        pe_module.parse_data_directories(
            directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"]]
        )
        if not hasattr(pe_module, "DIRECTORY_ENTRY_EXPORT"):
            return None

        return ExportSymbolFinder(
            layer_name,
            mod_name.lower(),
            module_start,
            pe_module.DIRECTORY_ENTRY_EXPORT.symbols,
        )

    @staticmethod
    def _get_pdb_module(
        context: interfaces.context.ContextInterface,
        config_path: str,
        mod_name: str,
        module_info: collected_module_instance,
    ) -> Optional[PDBSymbolFinder]:
        """
        Attempts to locate symbols based on PDB analysis through each layer where the mod_name module was found

        Args:
            mod_name: lower case name of the module to resolve symbols in
            module_info: (layer_name, module_start, module_size) of the module to examine

        Returns:
            Optional[PDBSymbolFinder]: If the export table can be resolved, then the ExportSymbolFinder
        """

        mod_symbols = None

        layer_name, module_start, module_size = module_info

        # the PDB name of the kernel file is not consistent for an exe, for example,
        # a `ntoskrnl.exe` can have an internal PDB name of any of the ones in the following list
        # The code attempts to find all possible PDBs to ensure the best chance of recovery
        if mod_name == PESymbols.os_module_name:
            pdb_names = [fn + ".pdb" for fn in KERNEL_MODULE_NAMES]

        # for non-kernel files, replace the exe, sys, or dll extension with pdb
        else:
            # in testing we found where some DLLs, such amsi.dll, have its PDB string as Amsi.dll
            # in certain Windows versions
            mod_name = mod_name[:-3] + "pdb"
            first_upper = mod_name[0].upper() + mod_name[1:]
            pdb_names = [mod_name, first_upper]

        # loop through each PDB name (all the kernel names or the dll name as lower() + first char upper case)
        for pdb_name in pdb_names:
            try:
                mod_symbols = pdbutil.PDBUtility.symbol_table_from_pdb(
                    context,
                    interfaces.configuration.path_join(config_path, mod_name),
                    layer_name,
                    pdb_name,
                    module_start,
                    module_size,
                )

                if mod_symbols:
                    break

            # this exception is expected when the PDB can't be found or downloaded
            except exceptions.VolatilityException:
                continue

            # this is not expected - it means pdbconv broke when parsing the PDB
            except TypeError as e:
                vollog.error(
                    f"Unable to parse PDB file for module {pdb_name} -> {e}. Please file a bug on the GitHub issue tracker."
                )

        # cannot do anything without the symbols
        if not mod_symbols:
            return None

        pdb_module = context.module(
            mod_symbols, layer_name=layer_name, offset=module_start
        )

        return PDBSymbolFinder(layer_name, mod_name, module_start, pdb_module)

    @staticmethod
    def _find_symbols_through_pdb(
        context: interfaces.context.ContextInterface,
        config_path: str,
        module_instances: collected_modules_info,
        mod_name: str,
    ) -> Generator[PDBSymbolFinder, None, None]:
        """
        Attempts to resolve the symbols in `mod_name` through PDB analysis

        Args:
            module_instances: the set of layers in which the module was found
            mod_name: name of the module to resolve symbols in
        Returns:
            Generator[PDBSymbolFinder]: a PDBSymbolFinder instance for each layer in which the module was found
        """
        for module_info in module_instances:
            mod_module = PESymbols._get_pdb_module(
                context, config_path, mod_name, module_info
            )
            if mod_module:
                yield mod_module

    @staticmethod
    def _find_symbols_through_exports(
        context: interfaces.context.ContextInterface,
        config_path: str,
        module_instances: collected_modules_info,
        mod_name: str,
    ) -> Generator[ExportSymbolFinder, None, None]:
        """
        Attempts to resolve the symbols in `mod_name` through export analysis

        Args:
            module_instances: the set of layers in which the module was found
            mod_name: name of the module to resolve symbols in
        Returns:
            Generator[ExportSymbolFinder]: an ExportSymbolFinder instance for each layer in which the module was found
        """
        pe_table_name = intermed.IntermediateSymbolTable.create(
            context, config_path, "windows", "pe", class_types=pe.class_types
        )

        # for each process layer and VAD, construct a PE and examine the export table
        for module_info in module_instances:
            exported_symbols = PESymbols._get_exported_symbols(
                context, pe_table_name, mod_name, module_info
            )
            if exported_symbols:
                yield exported_symbols

    @staticmethod
    def _get_symbol_value(
        wanted_symbols: filter_module_info,
        symbol_resolver: PESymbolFinder,
    ) -> Generator[Tuple[str, int, str, int], None, None]:
        """
        Enumerates the symbols specified as wanted by the calling plugin

        Args:
            wanted_symbols: the set of symbols for a particular module
            symbol_resolver: method in a layer to resolve the symbols

        Returns:
            Tuple[str, int, str, int]: the index and value of the found symbol in the wanted list, and the name and address of resolved symbol
        """
        if (
            wanted_names_identifier not in wanted_symbols
            and wanted_addresses_identifier not in wanted_symbols
        ):
            vollog.warning(
                f"Invalid `wanted_symbols` sent to `find_symbols`. addresses and names keys both misssing."
            )
            return

        symbol_keys: List[Tuple[str, Callable]] = [
            (wanted_names_identifier, symbol_resolver.get_address_for_name),
            (wanted_addresses_identifier, symbol_resolver.get_name_for_address),
        ]

        for symbol_key, symbol_getter in symbol_keys:
            # address or name
            if symbol_key in wanted_symbols:
                # walk each wanted address or name
                for value_index, wanted_value in enumerate(wanted_symbols[symbol_key]):
                    symbol_value = symbol_getter(wanted_value)

                    if symbol_value:
                        # yield out deleteion key, deletion index, symbol name, symbol address
                        if symbol_key == wanted_names_identifier:
                            yield symbol_key, value_index, wanted_value, symbol_value  # type: ignore
                        else:
                            yield symbol_key, value_index, symbol_value, wanted_value  # type: ignore

    @staticmethod
    def _resolve_symbols_through_methods(
        context: interfaces.context.ContextInterface,
        config_path: str,
        module_instances: collected_modules_info,
        wanted_modules: PESymbolFinder.cached_value_dict,
        mod_name: str,
    ) -> Tuple[found_symbols_module, PESymbolFinder.cached_module_lists]:
        """
        Attempts to resolve every wanted symbol in `mod_name`
        Every layer is enumerated for maximum chance of recovery

        Args:
            module_instances: the set of layers in which the module was found
            wanted_modules: The symbols to resolve tied to their module names
            mod_name: name of the module to resolve symbols in
        Returns:
            Tuple[found_symbols_module, PESymbolFinder.cached_module_lists]: The set of found symbols and the ones that could not be resolved
        """
        symbol_resolving_methods = [
            PESymbols._find_symbols_through_pdb,
            PESymbols._find_symbols_through_exports,
        ]

        found: found_symbols_module = []

        # the symbols wanted from this module by the caller
        wanted = wanted_modules[mod_name]

        # make a copy to remove from inside this function for returning to the caller
        remaining = copy.deepcopy(wanted)

        for method in symbol_resolving_methods:
            # every layer where this module was found through the given method
            for symbol_resolver in method(
                context, config_path, module_instances, mod_name
            ):
                vollog.debug(f"Have resolver for method {method}")
                for (
                    symbol_key,
                    value_index,
                    symbol_name,
                    symbol_address,
                ) in PESymbols._get_symbol_value(remaining, symbol_resolver):
                    found.append((symbol_name, symbol_address))
                    del remaining[symbol_key][value_index]

                # everything was resolved, stop this resolver
                if not remaining[symbol_key]:
                    break

            # stop all resolving
            if not remaining[symbol_key]:
                del remaining[symbol_key]
                break

        return found, remaining

    @staticmethod
    def find_symbols(
        context: interfaces.context.ContextInterface,
        config_path: str,
        wanted_modules: PESymbolFinder.cached_value_dict,
        collected_modules: collected_modules_type,
    ) -> Tuple[found_symbols_type, PESymbolFinder.cached_value_dict]:
        """
        Loops through each method of symbol analysis until each wanted symbol is found
        Returns the resolved symbols as a dictionary that includes the name and runtime address

        Args:
            wanted_modules: the dictionary of modules and symbols to resolve. Modified to remove symbols as they are resolved.
            collected_modules: return value from `get_kernel_modules` or `get_process_modules`
        Returns:
            Tuple[found_symbols_type, PESymbolFinder.cached_value_dict]: The set of found symbols but the ones that could not be resolved
        """
        found_symbols: found_symbols_type = {}
        missing_symbols: PESymbolFinder.cached_value_dict = {}

        for mod_name in wanted_modules:
            if mod_name not in collected_modules:
                continue

            module_instances = collected_modules[mod_name]

            # try to resolve the symbols for `mod_name` through each method (PDB and export table currently)
            (
                found_in_module,
                missing_in_module,
            ) = PESymbols._resolve_symbols_through_methods(
                context, config_path, module_instances, wanted_modules, mod_name
            )

            if found_in_module:
                found_symbols[mod_name] = found_in_module

            if missing_in_module:
                missing_symbols[mod_name] = missing_in_module

        return found_symbols, missing_symbols

    @staticmethod
    def get_kernel_modules(
        context: interfaces.context.ContextInterface,
        layer_name: str,
        symbol_table: str,
        filter_modules: Optional[filter_modules_type],
    ) -> collected_modules_type:
        """
        Walks the kernel module list and finds the session layer, base, and size of each wanted module

        Args:
            filter_modules: The modules to filter the gathering to. If left as None, all kernel modules are gathered.
        Returns:
            collected_modules_type: The collection of modules found with at least one layer present
        """
        found_modules: collected_modules_type = {}

        if filter_modules:
            # create a tuple of module names for use with `endswith`
            filter_modules_check = tuple([key.lower() for key in filter_modules.keys()])
        else:
            filter_modules_check = None

        session_layers = list(
            modules.Modules.get_session_layers(context, layer_name, symbol_table)
        )

        # special handling for the kernel
        gather_kernel = (
            filter_modules_check and PESymbols.os_module_name in filter_modules_check
        )

        for index, mod in enumerate(
            modules.Modules.list_modules(context, layer_name, symbol_table)
        ):
            try:
                mod_name = str(mod.BaseDllName.get_string().lower())
            except exceptions.InvalidAddressException:
                continue

            # to analyze, it must either be the kernel or a wanted module
            if not filter_modules_check or (gather_kernel and index == 0):
                mod_name = PESymbols.os_module_name
            elif filter_modules_check and not mod_name.endswith(filter_modules_check):
                continue

            # we won't find symbol information if we can't analyze the module
            session_layer_name = modules.Modules.find_session_layer(
                context, session_layers, mod.DllBase
            )
            if not session_layer_name:
                continue

            if mod_name not in found_modules:
                found_modules[mod_name] = []

            found_modules[mod_name].append(
                (session_layer_name, mod.DllBase, mod.SizeOfImage)
            )

        return found_modules

    @staticmethod
    def get_vads_for_process_cache(
        vads_cache: Dict[int, ranges_type],
        owner_proc: interfaces.objects.ObjectInterface,
    ) -> Optional[ranges_type]:
        """
        Creates and utilizes a cache of a process' VADs for efficient lookups

        Returns the vad information of the VAD hosting the address, if found

        Args:
            vads_cache: The existing cache of VADs
            owner_proc: The process being inspected
        Returns:
            Optional[ranges_type]: The range holding the address, if found
        """
        if owner_proc.vol.offset in vads_cache:
            vads = vads_cache[owner_proc.vol.offset]
        else:
            vads = PESymbols.get_proc_vads_with_file_paths(owner_proc)
            vads_cache[owner_proc.vol.offset] = vads

        # smear or terminated process
        if len(vads) == 0:
            return None

        return vads

    @staticmethod
    def get_proc_vads_with_file_paths(
        proc: interfaces.objects.ObjectInterface,
    ) -> ranges_type:
        """
        Returns a list of the process' vads that map a file

        Args:
            proc: The process to gather the VADs for

        Returns:
            ranges_type: The list of VADs for this process that map a file
        """
        vads: ranges_type = []

        try:
            vad_root = proc.get_vad_root()
        except exceptions.InvalidAddressException:
            return vads

        for vad in vad_root.traverse():
            filepath = vad.get_file_name()
            if not isinstance(filepath, str) or filepath.count("\\") == 0:
                continue

            vads.append((vad.get_start(), vad.get_size(), filepath))

        return vads

    @classmethod
    def get_all_vads_with_file_paths(
        cls,
        context: interfaces.context.ContextInterface,
        layer_name: str,
        symbol_table_name: str,
    ) -> Generator[
        Tuple[interfaces.objects.ObjectInterface, str, ranges_type],
        None,
        None,
    ]:
        """
        Yields each set of vads for a process that have a file mapped, along with the process itself and its layer

        Args:
            Generator[Tuple[interfaces.objects.ObjectInterface, str, ranges_type]]: Yields tuple of process objects, layers, and VADs mapping files
        """
        procs = pslist.PsList.list_processes(
            context=context,
            layer_name=layer_name,
            symbol_table=symbol_table_name,
        )

        for proc in procs:
            try:
                proc_layer_name = proc.add_process_layer()
            except exceptions.InvalidAddressException:
                continue

            vads = cls.get_proc_vads_with_file_paths(proc)

            yield proc, proc_layer_name, vads

    @staticmethod
    def get_process_modules(
        context: interfaces.context.ContextInterface,
        layer_name: str,
        symbol_table: str,
        filter_modules: Optional[filter_modules_type],
    ) -> collected_modules_type:
        """
        Walks the process list and each process' VAD to determine the base address and size of wanted modules

        Args:
            filter_modules: The modules to filter the gathering to. If left as None, all process modules are gathered.
        Returns:
            collected_modules_type: The collection of modules found with at least one layer present
        """
        proc_modules: collected_modules_type = {}

        if filter_modules:
            # create a tuple of module names for use with `endswith`
            filter_modules_check = tuple([key.lower() for key in filter_modules.keys()])
        else:
            filter_modules_check = None

        for _proc, proc_layer_name, vads in PESymbols.get_all_vads_with_file_paths(
            context, layer_name, symbol_table
        ):
            for vad_start, vad_size, filepath in vads:
                filename = PESymbols.filename_for_path(filepath)

                if filter_modules_check and not filename.endswith(filter_modules_check):
                    continue

                # track each module along with the process layer and range to find it
                if filename not in proc_modules:
                    proc_modules[filename] = []

                proc_modules[filename].append((proc_layer_name, vad_start, vad_size))

        return proc_modules

    def _generator(self) -> Generator[Tuple[int, Tuple[str, str, int]], None, None]:
        kernel = self.context.modules[self.config["kernel"]]

        if self.config["symbols"]:
            filter_module = {
                self.config["module"].lower(): {
                    wanted_names_identifier: self.config["symbols"]
                }
            }

        elif self.config["addresses"]:
            filter_module = {
                self.config["module"].lower(): {
                    wanted_addresses_identifier: self.config["addresses"]
                }
            }

        else:
            vollog.error("--address or --symbol must be specified")
            return

        if self.config["source"] == "kernel":
            module_resolver = self.get_kernel_modules
        else:
            module_resolver = self.get_process_modules

        collected_modules = module_resolver(
            self.context, kernel.layer_name, kernel.symbol_table_name, filter_module
        )

        found_symbols, _missing_symbols = PESymbols.find_symbols(
            self.context, self.config_path, filter_module, collected_modules
        )

        for module, symbols in found_symbols.items():
            for symbol, address in symbols:
                yield (0, (module, symbol, format_hints.Hex(address)))

    def run(self) -> renderers.TreeGrid:
        return renderers.TreeGrid(
            [
                ("Module", str),
                ("Symbol", str),
                ("Address", format_hints.Hex),
            ],
            self._generator(),
        )
