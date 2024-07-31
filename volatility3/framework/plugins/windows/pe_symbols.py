# This file is Copyright 2024 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0

import io
import logging
from typing import Dict, Tuple, Optional, List

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

# used for special handling of the kernel PDB file. See later notes
os_module_name = "ntoskrnl.exe"


class PESymbols(interfaces.plugins.PluginInterface):
    """Prints symbols in PE files in process and kernel memory"""

    _required_framework_version = (2, 7, 0)

    @classmethod
    def get_requirements(cls):
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
                optional=False,
            ),
        ]

    @staticmethod
    def _get_pefile_obj(
        context, pe_table_name: str, layer_name: str, base_address: int
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
    def _find_through_exports(
        context,
        config_path: str,
        mod_name: str,
        vads: Tuple[int, int, int],
        wanted_symbols: Dict[str, List[str]],
        found_symbols: Dict[str, Tuple[str, int]],
    ):
        """
        Attempts to resolve the symbols in `wanted_symbols` through export table analysis
        wanted_symbols is a dictionary of lower case DLL names, whose values are a list of symbols
        to resolve per-DLL. Example from apihooks:

        userland_apis = {
            "wininet.dll": [
                "HttpSendRequestA",
                "HttpSendRequestW",
                "HttpSendRequestExA",
                ...
                ],

            "kernel32.dll": [
                "GetProcAddress",
                "LoadLibrary",
                "LoadLibraryA",
                "LoadLibraryExA",
                ...
                ],
        }

        found_symbols is populated with symbols as they are resolved.
        It holds a dictionary of DLL names and its values are a list of
        (function name, runtime address) of each symbol found
        """
        pe_table_name = intermed.IntermediateSymbolTable.create(
            context, config_path, "windows", "pe", class_types=pe.class_types
        )

        # for each process layer and VAD, construct a PE and examine the export table
        for proc_layer_name, vad_start, _ in vads:
            # we need a valid PE with an export table
            pe_module = PESymbols._get_pefile_obj(
                context, pe_table_name, proc_layer_name, vad_start
            )
            if not pe_module:
                continue

            pe_module.parse_data_directories(
                directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"]]
            )
            if not hasattr(pe_module, "DIRECTORY_ENTRY_EXPORT"):
                continue

            # walk the export table looking for symbols of interest
            for export in pe_module.DIRECTORY_ENTRY_EXPORT.symbols:
                # AttributeError throws on empty or ordinal-only exports
                try:
                    func = export.name.decode("ascii")
                except AttributeError:
                    continue

                if func in wanted_symbols[mod_name]:
                    address = export.address

                    if mod_name not in found_symbols:
                        found_symbols[mod_name] = []

                    found_symbols[mod_name].append((func, vad_start + address))
                    wanted_symbols[mod_name].remove(func)

                    # stop processing the layers (processes) if we found all the symbols for this module
                    if not wanted_symbols[mod_name]:
                        return

    @staticmethod
    def _find_through_pdb(
        context,
        config_path: str,
        mod_name: str,
        vads: Tuple[int, int, int],
        wanted_symbols: Dict[str, List[str]],
        found_symbols: Dict[str, Tuple[str, int]],
    ):
        """
        Attempts to resolve the symbols in `wanted_symbols` through PDB analysis
        """

        # the PDB name of the kernel file is not consistent for an exe, for example,
        # a `ntoskrnl.exe` can have an internal PDB name of any of the ones in the following list
        # The code attempts to find all possible PDBs to ensure the best chance of recovery
        if mod_name == os_module_name:
            pdb_names = ["ntkrnlmp.pdb", "ntkrnlpa.pdb", "ntkrpamp.pdb", "ntoskrnl.pdb"]

        # for non-kernel files, replace the exe, sys, or dll extension with pdb
        else:
            pdb_names = [mod_name[:-3] + "pdb"]

        for proc_layer_name, vad_start, vad_size in vads:
            mod_symbols = None

            # loop through each PDB name (will be just one for all but the kernel)
            for pdb_name in pdb_names:
                try:
                    mod_symbols = pdbutil.PDBUtility.symbol_table_from_pdb(
                        context,
                        interfaces.configuration.path_join(config_path, mod_name),
                        proc_layer_name,
                        pdb_name,
                        vad_start,
                        vad_size,
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
                continue

            mod_module = context.module(
                mod_symbols, layer_name=proc_layer_name, offset=vad_start
            )

            # loop through each export looking for ones of interest
            # break early if they are alll found
            for func in wanted_symbols[mod_name]:
                try:
                    address = mod_module.get_symbol(func).address
                except exceptions.SymbolError:
                    continue

                if mod_name not in found_symbols:
                    found_symbols[mod_name] = []

                found_symbols[mod_name].append((func, vad_start + address))
                wanted_symbols[mod_name].remove(func)

            # stop processing the layers (processes) if we found all the symbols for this module
            if not wanted_symbols[mod_name]:
                break

    @staticmethod
    def find_function_offsets(
        context,
        config_path: str,
        layer_name: str,
        symbol_table: str,
        module_collector,
        wanted_symbols: Dict[str, List[str]],
    ) -> Dict[str, Tuple[str, int]]:
        """
        Loops through each method of symbol analysis until each wanted symbol is found
        Returns the resolved symbols as a dictionary that includes the name and runtime address
        """
        found_symbols = {}

        methods = [PESymbols._find_through_pdb, PESymbols._find_through_exports]

        collected_modules = module_collector(
            context, layer_name, symbol_table, wanted_symbols
        )

        # loop through each wanted module and its symbols
        for mod_name, vads in collected_modules.items():
            for method in methods:
                method(
                    context, config_path, mod_name, vads, wanted_symbols, found_symbols
                )

                # stop processing this DLL if/when all symbols are found
                if not wanted_symbols[mod_name]:
                    del wanted_symbols[mod_name]
                    break

        return found_symbols

    @staticmethod
    def get_wanted_kernel_modules(
        context,
        layer_name: str,
        symbol_table: str,
        wanted_symbols: Dict[str, List[str]],
    ) -> Dict[str, Tuple[str, int, int]]:
        """
        Walks the kernel module list and finds the session layer, base, and size of each wanted module
        """
        found_modules = {}

        # create a tuple of module names for use with `endswith`
        wanted_modules = tuple([key.lower() for key in wanted_symbols.keys()])

        session_layers = list(
            modules.Modules.get_session_layers(context, layer_name, symbol_table)
        )

        # special handling for the kernel
        gather_kernel = os_module_name in wanted_modules

        for index, mod in enumerate(
            modules.Modules.list_modules(context, layer_name, symbol_table)
        ):
            try:
                mod_name = mod.BaseDllName.get_string().lower()
            except exceptions.InvalidAddressException:
                continue

            # to analyze, it must either be the kernel or a wanted module
            if gather_kernel and index == 0:
                mod_name = os_module_name
            elif not mod_name.endswith(wanted_modules):
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
    def get_wanted_process_modules(
        context,
        layer_name: str,
        symbol_table: str,
        wanted_symbols: Dict[str, List[str]],
    ) -> Dict[str, Tuple[str, int, int]]:
        """
        Walks the process list and each process' VAD to determine the base address and size of wanted modules
        """
        proc_modules = {}

        # create a tuple of module names for use with `endswith`
        wanted_modules = tuple([key.lower() for key in wanted_symbols.keys()])

        procs = pslist.PsList.list_processes(
            context=context,
            layer_name=layer_name,
            symbol_table=symbol_table,
        )

        # walk the process list gathering processes that map the DLL(s) of interest
        for proc in procs:
            try:
                proc_layer_name = proc.add_process_layer()
            except exceptions.InvalidAddressException:
                continue

            for vad in proc.get_vad_root().traverse():
                filepath = vad.get_file_name()
                if not isinstance(filepath, str) or filepath.count("\\") == 0:
                    continue

                # track each module along with the process layer and range to find it
                filename = filepath.lower().split("\\")[-1]
                if filename.endswith(wanted_modules):
                    if filename not in proc_modules:
                        proc_modules[filename] = []

                    proc_modules[filename].append(
                        (proc_layer_name, vad.get_start(), vad.get_size())
                    )

        return proc_modules

    @staticmethod
    def resolve_wanted_process_symbols(
        context,
        config_path: str,
        layer_name: str,
        symbol_table: str,
        wanted_symbols: Dict[str, List[str]],
    ) -> Dict[str, Tuple[str, int]]:
        """
        Wrapper around `find_function_offsets` to gather process symbols
        """

        return PESymbols.find_function_offsets(
            context,
            config_path,
            layer_name,
            symbol_table,
            PESymbols.get_wanted_process_modules,
            wanted_symbols,
        )

    @staticmethod
    def resolve_wanted_kernel_symbols(
        context,
        config_path,
        layer_name,
        symbol_table,
        wanted_symbols,
    ) -> Dict[str, Tuple[str, int]]:
        """
        Wrapper around `find_function_offsets` to gather kernel symbols
        """

        return PESymbols.find_function_offsets(
            context,
            config_path,
            layer_name,
            symbol_table,
            PESymbols.get_wanted_kernel_modules,
            wanted_symbols,
        )

    def _generator(self):
        kernel = self.context.modules[self.config["kernel"]]

        wanted_symbols = {self.config["module"].lower(): [self.config["symbol"]]}

        if self.config["source"] == "kernel":
            generator = self.resolve_wanted_kernel_symbols
        else:
            generator = self.resolve_wanted_process_symbols

        found_symbols = generator(
            self.context,
            self.config_path,
            kernel.layer_name,
            kernel.symbol_table_name,
            wanted_symbols,
        )

        for module, symbols in found_symbols.items():
            for symbol, address in symbols:
                yield (0, (module, symbol, format_hints.Hex(address)))

    def run(self):
        return renderers.TreeGrid(
            [
                ("Module", str),
                ("Symbol", str),
                ("Address", format_hints.Hex),
            ],
            self._generator(),
        )
