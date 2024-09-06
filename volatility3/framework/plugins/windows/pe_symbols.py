# This file is Copyright 2024 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0


import io
import logging

from typing import Dict, Tuple, Optional, List, Generator, Union

import pefile

from volatility3.framework import interfaces, exceptions
from volatility3.framework import renderers, constants
from volatility3.framework.configuration import requirements
from volatility3.framework.renderers import format_hints
from volatility3.framework.symbols import intermed
from volatility3.framework.symbols.windows import pdbutil
from volatility3.framework.symbols.windows.extensions import pe
from volatility3.plugins.windows import pslist, vadinfo, modules

vollog = logging.getLogger(__name__)


class PESymbolFinder:
    """
    Interface for PE symbol finding classes
    This interface provides a standard way for the calling code to
    lookup symbols by name or address
    """

    cached_str = Union[str, None]
    cached_str_dict = Dict[str, cached_str]

    cached_int = Union[int, None]
    cached_int_dict = Dict[str, cached_int]

    cached_value = Union[int, str, None]
    cached_value_dict = Dict[str, Union[Dict[str, List[str]], Dict[str, List[int]]]]

    def __init__(
        self,
        layer_name: str,
        mod_name: str,
        module_start: int,
        symbol_module: Union[interfaces.context.ModuleInterface, pefile.ExportDirData],
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
        """
        return f"{self._layer_name}|{self._mod_name}|{value}"

    def get_name_for_address(self, address: int) -> cached_str:
        cached_key = self._get_cache_key(address)
        if cached_key not in self._name_cache:
            name = self._do_get_name(address)
            self._name_cache[cached_key] = name

        return self._name_cache[cached_key]

    def get_address_for_name(self, name: str) -> cached_int:
        cached_key = self._get_cache_key(name)
        if cached_key not in self._address_cache:
            address = self._do_get_address(name)
            self._address_cache[cached_key] = address

        return self._address_cache[cached_key]

    def _do_get_name(self, address: int) -> cached_str:
        raise NotImplementedError("_do_get_name must be overwritten")

    def _do_get_address(self, name: str) -> cached_int:
        raise NotImplementedError("_do_get_address must be overwritten")


class PDBSymbolFinder(PESymbolFinder):
    """
    PESymbolFinder implementation for  PDB modules
    """

    def _do_get_address(self, name: str) -> PESymbolFinder.cached_int:
        try:
            return self._symbol_module.get_absolute_symbol_address(name)
        except exceptions.SymbolError:
            return None

    def _do_get_name(self, address: int) -> PESymbolFinder.cached_str:
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

    def _do_get_name(self, address: int) -> PESymbolFinder.cached_str:
        for export in self._symbol_module:
            if export.address + self._module_start == address:
                return self._get_name(export)

        return None

    def _do_get_address(self, name: str) -> PESymbolFinder.cached_int:
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

    # keys for specifying wanted names and/or addresses
    # used for consistent access between the API and plugins
    wanted_names = "names"
    wanted_addresses = "addresses"

    # how wanted modules/symbols are specified, such as:
    # {"ntdll.dll" : {wanted_addresses : [42, 43, 43]}}
    # {"ntdll.dll" : {wanted_names : ["NtCreateThread"]}}
    filter_modules_type = Dict[str, Union[Dict[str, List[str]], Dict[str, List[int]]]]

    # holds resolved symbols
    # {"ntdll.dll": [("Bob", 123), ("Alice", 456)]}
    found_symbols_type = Dict[str, List[Tuple[str, int]]]

    # used to hold informatin about a range (VAD or kernel module)
    # (start address, size, file path)
    range_type = Tuple[int, int, str]
    ranges_type = List[range_type]

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
                name="vadinfo", component=vadinfo.VadInfo, version=(2, 0, 0)
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
            requirements.StringRequirement(
                name="symbol",
                description="Symbol name to resolve",
                optional=True,
            ),
            requirements.IntRequirement(
                name="address",
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
        Helper for getting the range information for an address
        """
        for start, size, filepath in ranges:
            if start <= address < start + size:
                return start, size, filepath

        return None

    @staticmethod
    def filepath_for_address(ranges: ranges_type, address: int) -> Optional[str]:
        """
        Helper to get the file path for an address
        """
        info = PESymbols.range_info_for_address(ranges, address)
        if info:
            return info[2]

        return None

    @staticmethod
    def filename_for_path(filepath: str) -> str:
        """
        Consistent way to get the filename
        """
        return filepath.split("\\")[-1]

    @staticmethod
    def addresses_for_process_symbols(
        context: interfaces.context.ContextInterface,
        config_path: str,
        layer_name: str,
        symbol_table_name: str,
        symbols: filter_modules_type,
    ) -> found_symbols_type:
        collected_modules = PESymbols.get_process_modules(
            context, layer_name, symbol_table_name, symbols
        )

        found_symbols = PESymbols.find_symbols(
            context, config_path, symbols, collected_modules
        )

        for mod_name, unresolved_symbols in symbols.items():
            for symbol in unresolved_symbols:
                vollog.debug(f"Unable to resolve symbol {symbol} in module {mod_name}")

        return found_symbols

    @staticmethod
    def path_and_symbol_for_address(
        context: interfaces.context.ContextInterface,
        config_path: str,
        collected_modules: Dict[str, List[Tuple[str, int, int]]],
        ranges: ranges_type,
        address: int,
    ) -> Tuple[str, str]:
        """
        Method for plugins to determine the file path and symbol name for a given address

        collected_modules: return value from `get_kernel_modules` or `get_process_modules`
        ranges: the memory ranges to examine in this layer.
        address: address to resolve to its symbol name
        """

        if not address:
            return renderers.NotApplicableValue(), renderers.NotApplicableValue()

        filepath = PESymbols.filepath_for_address(ranges, address)

        if not filepath:
            return renderers.NotAvailableValue(), renderers.NotAvailableValue()

        filename = PESymbols.filename_for_path(filepath).lower()

        # setup to resolve the address
        filter_module: PESymbols.filter_modules_type = {
            filename: {PESymbols.wanted_addresses: [address]}
        }

        found_symbols = PESymbols.find_symbols(
            context, config_path, filter_module, collected_modules
        )

        if not found_symbols or not found_symbols[filename]:
            return renderers.NotAvailableValue(), renderers.NotAvailableValue()

        return filepath, found_symbols[filename][0][0]

    @staticmethod
    def _get_exported_symbols(
        context: interfaces.context.ContextInterface,
        pe_table_name: str,
        mod_name: str,
        module_info: Tuple[str, int, int],
    ) -> Optional[ExportSymbolFinder]:
        """
        Attempts to locate symbols based on export analysis

        mod_name: lower case name of the module to resolve symbols in
        module_info: (layer_name, module_start, module_size) of the module to examine
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
            layer_name, mod_name, module_start, pe_module.DIRECTORY_ENTRY_EXPORT.symbols
        )

    @staticmethod
    def _get_pdb_module(
        context: interfaces.context.ContextInterface,
        config_path: str,
        mod_name: str,
        module_info: Tuple[str, int, int],
    ) -> Optional[PDBSymbolFinder]:
        """
        Attempts to locate symbols based on PDB analysis

        mod_name: lower case name of the module to resolve symbols in
        module_info: (layer_name, module_start, module_size) of the module to examine
        """

        mod_symbols = None

        layer_name, module_start, module_size = module_info

        # the PDB name of the kernel file is not consistent for an exe, for example,
        # a `ntoskrnl.exe` can have an internal PDB name of any of the ones in the following list
        # The code attempts to find all possible PDBs to ensure the best chance of recovery
        if mod_name == PESymbols.os_module_name:
            pdb_names = ["ntkrnlmp.pdb", "ntkrnlpa.pdb", "ntkrpamp.pdb", "ntoskrnl.pdb"]

        # for non-kernel files, replace the exe, sys, or dll extension with pdb
        else:
            mod_name = mod_name[:-3] + "pdb"
            first_upper = mod_name[0].upper() + mod_name[1:]
            pdb_names = [mod_name, first_upper]

        # loop through each PDB name (will be just one for all but the kernel)
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
        module_instances: List[Tuple[str, int, int]],
        mod_name: str,
    ) -> Generator[PDBSymbolFinder, None, None]:
        """
        Attempts to resolve the symbols in `wanted_symbols` through PDB analysis
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
        module_instances: List[Tuple[str, int, int]],
        mod_name: str,
    ) -> Generator[ExportSymbolFinder, None, None]:
        """
        Attempts to resolve the symbols in `wanted_symbols` through export analysis
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
        wanted_modules: PESymbolFinder.cached_value_dict,
        mod_name: str,
        symbol_resolver: PESymbolFinder,
    ) -> Generator[Tuple[str, int], None, None]:
        """
        Enumerates the symbols specified as wanted by the calling plugin
        """
        wanted_symbols = wanted_modules[mod_name]

        if (
            PESymbols.wanted_names not in wanted_symbols
            and PESymbols.wanted_addresses not in wanted_symbols
        ):
            vollog.warning(
                f"Invalid `wanted_symbols` sent to `find_symbols` for module {mod_name}. addresses and names keys both misssing."
            )
            return

        symbol_keys = [
            (PESymbols.wanted_names, "get_address_for_name"),
            (PESymbols.wanted_addresses, "get_name_for_address"),
        ]

        for symbol_key, symbol_getter in symbol_keys:
            # address or name
            if symbol_key in wanted_symbols:
                # walk each wanted address or name
                for wanted_value in wanted_symbols[symbol_key]:
                    symbol_value = symbol_resolver.__getattribute__(symbol_getter)(
                        wanted_value
                    )
                    if symbol_value:
                        # yield out symbol name, symbol address
                        if symbol_key == PESymbols.wanted_names:
                            yield wanted_value, symbol_value  # type: ignore
                        else:
                            yield symbol_value, wanted_value  # type: ignore

                        index = wanted_modules[mod_name][symbol_key].index(wanted_value)  # type: ignore

                        del wanted_modules[mod_name][symbol_key][index]

                # if all names or addresses from a module are found, delete the key
                if not wanted_modules[mod_name][symbol_key]:
                    del wanted_modules[mod_name][symbol_key]
                    break

    @staticmethod
    def _resolve_symbols_through_methods(
        context: interfaces.context.ContextInterface,
        config_path: str,
        module_instances: List[Tuple[str, int, int]],
        wanted_modules: PESymbolFinder.cached_value_dict,
        mod_name: str,
    ) -> Generator[Tuple[str, int], None, None]:
        """
        Attempts to resolve every wanted symbol in `mod_name`
        Every layer is enumerated for maximum chance of recovery
        """
        symbol_resolving_methods = [
            PESymbols._find_symbols_through_pdb,
            PESymbols._find_symbols_through_exports,
        ]

        for method in symbol_resolving_methods:
            for symbol_resolver in method(
                context, config_path, module_instances, mod_name
            ):
                vollog.debug(f"Have resolver for method {method}")
                yield from PESymbols._get_symbol_value(
                    wanted_modules, mod_name, symbol_resolver
                )

                if not wanted_modules[mod_name]:
                    break

            if not wanted_modules[mod_name]:
                break

    @staticmethod
    def find_symbols(
        context: interfaces.context.ContextInterface,
        config_path: str,
        wanted_modules: PESymbolFinder.cached_value_dict,
        collected_modules: Dict[str, List[Tuple[str, int, int]]],
    ) -> found_symbols_type:
        """
        Loops through each method of symbol analysis until each wanted symbol is found
        Returns the resolved symbols as a dictionary that includes the name and runtime address
        """
        found_symbols: PESymbols.found_symbols_type = {}

        for mod_name in wanted_modules:
            if mod_name not in collected_modules:
                continue

            module_instances = collected_modules[mod_name]

            # try to resolve the symbols for `mod_name` through each method (PDB and export table currently)
            for symbol_name, address in PESymbols._resolve_symbols_through_methods(
                context, config_path, module_instances, wanted_modules, mod_name
            ):
                if mod_name not in found_symbols:
                    found_symbols[mod_name] = []

                found_symbols[mod_name].append((symbol_name, address))

                # stop processing the layers (processes) if we found all the symbols for this module
                if not wanted_modules[mod_name]:
                    break

            # stop processing this module if/when all symbols are found
            if not wanted_modules[mod_name]:
                del wanted_modules[mod_name]
                break

        return found_symbols

    @staticmethod
    def get_kernel_modules(
        context: interfaces.context.ContextInterface,
        layer_name: str,
        symbol_table: str,
        filter_modules: Optional[filter_modules_type],
    ) -> Dict[str, List[Tuple[str, int, int]]]:
        """
        Walks the kernel module list and finds the session layer, base, and size of each wanted module
        """
        found_modules: Dict[str, List[Tuple[str, int, int]]] = {}

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
    def get_process_modules(
        context: interfaces.context.ContextInterface,
        layer_name: str,
        symbol_table: str,
        filter_modules: Optional[filter_modules_type],
    ) -> Dict[str, List[Tuple[str, int, int]]]:
        """
        Walks the process list and each process' VAD to determine the base address and size of wanted modules
        """
        proc_modules: Dict[str, List[Tuple[str, int, int]]] = {}

        if filter_modules:
            # create a tuple of module names for use with `endswith`
            filter_modules_check = tuple([key.lower() for key in filter_modules.keys()])
        else:
            filter_modules_check = None

        for _, proc_layer_name, vads in vadinfo.VadInfo.get_all_vads_with_file_paths(
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

        if self.config["symbol"]:
            filter_module = {
                self.config["module"].lower(): {
                    PESymbols.wanted_names: [self.config["symbol"]]
                }
            }

        elif self.config["address"]:
            filter_module = {
                self.config["module"].lower(): {
                    PESymbols.wanted_addresses: [self.config["address"]]
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

        found_symbols = PESymbols.find_symbols(
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
