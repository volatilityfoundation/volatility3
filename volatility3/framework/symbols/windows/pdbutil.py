# This file is Copyright 2020 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

import binascii
import json
import logging
import lzma
import os
import re
import struct
from typing import Any, Dict, Generator, List, Optional, Tuple, Union
from urllib import parse, request

from volatility3 import symbols
from volatility3.framework import constants, contexts, exceptions, interfaces
from volatility3.framework.automagic import symbol_cache
from volatility3.framework.configuration import requirements
from volatility3.framework.configuration.requirements import SymbolTableRequirement
from volatility3.framework.symbols import intermed
from volatility3.framework.symbols.windows import pdbconv

vollog = logging.getLogger(__name__)


class PDBUtility(interfaces.configuration.VersionableInterface):
    """Class to handle and manage all getting symbols based on MZ header"""

    _version = (1, 0, 1)
    _required_framework_version = (2, 0, 0)

    @classmethod
    def symbol_table_from_offset(
        cls,
        context: interfaces.context.ContextInterface,
        layer_name: str,
        offset: int,
        symbol_table_class: str = "volatility3.framework.symbols.intermed.IntermediateSymbolTable",
        config_path: str = None,
        progress_callback: constants.ProgressCallback = None,
    ) -> Optional[str]:
        """Produces the name of a symbol table loaded from the offset for an MZ header

        Args:
            context: The context on which to operate
            layer_name: The name of the (contiguous) layer within the context that contains the MZ file
            offset: The offset in the layer at which the MZ file begins
            symbol_table_class: The class to use when constructing the SymbolTable
            config_path: New path for the produced symbol table configuration with the config tree
            progress_callback: Callable called to update ongoing progress

        Returns:
            None if no pdb information can be determined, else returned the name of the loaded symbols for the MZ
        """
        result = cls.get_guid_from_mz(context, layer_name, offset)
        if result is None:
            vollog.debug(f"Could not get GUID for {hex(offset)}")
            return None
        guid, age, pdb_name = result
        if config_path is None:
            config_path = interfaces.configuration.path_join(
                "pdbutility", pdb_name.replace(".", "_")
            )

        return cls.load_windows_symbol_table(
            context,
            guid,
            age,
            pdb_name,
            symbol_table_class,
            config_path,
            progress_callback,
        )

    @classmethod
    def load_windows_symbol_table(
        cls,
        context: interfaces.context.ContextInterface,
        guid: str,
        age: int,
        pdb_name: str,
        symbol_table_class: str,
        config_path: str = "pdbutility",
        progress_callback: constants.ProgressCallback = None,
    ):
        """Loads (downloading if necessary) a windows symbol table"""

        filter_string = os.path.join(
            pdb_name.strip("\x00"), guid.upper() + "-" + str(age)
        )

        isf_path = None
        # Take the first result of search for the intermediate file
        if not requirements.VersionRequirement.matches_required(
            (1, 0, 0), symbol_cache.SqliteCache.version
        ):
            vollog.debug(f"Required version of SQLiteCache not found")
            return None

        identifiers_path = os.path.join(
            constants.CACHE_PATH, constants.IDENTIFIERS_FILENAME
        )
        value = symbol_cache.SqliteCache(identifiers_path).find_location(
            symbol_cache.WindowsIdentifier.generate(
                pdb_name.strip("\x00"), guid.upper(), age
            ),
            "windows",
        )

        if value:
            isf_path = value
        else:
            # If none are found, attempt to download the pdb, convert it and try again
            cls.download_pdb_isf(
                context, guid.upper(), age, pdb_name, progress_callback
            )
            # Try again
            for value in intermed.IntermediateSymbolTable.file_symbol_url(
                "windows", filter_string
            ):
                isf_path = value
                break

        if not isf_path:
            vollog.debug(f"Required symbol library path not found: {filter_string}")
            vollog.info(
                "The symbols can be downloaded later using pdbconv.py -p {} -g {}".format(
                    pdb_name.strip("\x00"), guid.upper() + str(age)
                )
            )
            return None

        vollog.debug(f"Using symbol library: {filter_string}")

        # Set the discovered options
        join = interfaces.configuration.path_join
        context.config[join(config_path, "class")] = symbol_table_class
        context.config[join(config_path, "isf_url")] = isf_path
        parent_config_path = interfaces.configuration.parent_path(config_path)
        requirement_name = interfaces.configuration.path_head(config_path)

        # Construct the appropriate symbol table
        requirement = SymbolTableRequirement(
            name=requirement_name, description="PDBUtility generated symbol table"
        )
        requirement.construct(context, parent_config_path)
        return context.config[config_path]

    @classmethod
    def get_guid_from_mz(
        cls, context: interfaces.context.ContextInterface, layer_name: str, offset: int
    ) -> Optional[Tuple[str, int, str]]:
        """Takes the offset to an MZ header, locates any available pdb headers, and extracts the guid, age and pdb_name from them

        Args:
            context: The context on which to operate
            layer_name: The name of the (contiguous) layer within the context that contains the MZ file
            offset: The offset in the layer at which the MZ file begins

        Returns:
            A tuple of the guid, age and pdb_name, or None if no PDB record can be found
        """
        try:
            import pefile
        except ImportError:
            vollog.error(
                "Get_guid_from_mz requires the following python module: pefile"
            )
            return None

        layer = context.layers[layer_name]
        mz_sig = layer.read(offset, 2)

        # Check it is actually the MZ header
        if mz_sig != b"MZ":
            return None

        (nt_header_start,) = struct.unpack("<I", layer.read(offset + 0x3C, 4))
        pe_sig = layer.read(offset + nt_header_start, 2)

        # Check it is actually the Nt Headers
        if pe_sig != b"PE":
            return None

        (optional_header_size,) = struct.unpack(
            "<H", layer.read(offset + nt_header_start + 0x14, 2)
        )
        # Just enough to tell us the max size
        pe_header = layer.read(offset, nt_header_start + 0x16 + optional_header_size)
        pe_data = pefile.PE(data=pe_header)
        max_size = pe_data.OPTIONAL_HEADER.SizeOfImage

        # Proper data
        virtual_data = layer.read(offset, max_size, pad=True)
        pe_data = pefile.PE(data=virtual_data)

        # De-virtualize the memory
        sizeofHdrs = pe_data.OPTIONAL_HEADER.SizeOfHeaders
        physical_data = virtual_data[:sizeofHdrs]
        # Might need to put them in order by PointerToRawData just validate they are in order
        for sect in pe_data.sections:
            physical_data += virtual_data[
                sect.VirtualAddress : sect.VirtualAddress + sect.SizeOfRawData
            ]

        pe_data = pefile.PE(data=physical_data)

        if not hasattr(pe_data, "DIRECTORY_ENTRY_DEBUG") or not len(
            pe_data.DIRECTORY_ENTRY_DEBUG
        ):
            return None

        # Swap the Pointer with the Address since the de-virtualization doesn't apply to the fields
        debug_entry = None
        for index in range(len(pe_data.DIRECTORY_ENTRY_DEBUG)):
            if pe_data.DIRECTORY_ENTRY_DEBUG[index].struct.Type == 2:
                debug_data = pe_data.DIRECTORY_ENTRY_DEBUG[index]
                pe_data.set_dword_at_offset(
                    debug_data.struct.get_field_absolute_offset("AddressOfRawData"),
                    debug_data.struct.PointerToRawData,
                )
                pe_data.full_load()
                debug_entry = pe_data.DIRECTORY_ENTRY_DEBUG[index].entry

        if debug_entry is None:
            return None

        pdb_name = debug_entry.PdbFileName.decode("utf-8").strip("\x00")
        age = debug_entry.Age
        guid = "{:08x}{:04x}{:04x}{}".format(
            debug_entry.Signature_Data1,
            debug_entry.Signature_Data2,
            debug_entry.Signature_Data3,
            binascii.hexlify(debug_entry.Signature_Data4).decode("utf-8"),
        )
        return guid, age, pdb_name

    @classmethod
    def download_pdb_isf(
        cls,
        context: interfaces.context.ContextInterface,
        guid: str,
        age: int,
        pdb_name: str,
        progress_callback: constants.ProgressCallback = None,
    ) -> None:
        """Attempts to download the PDB file, convert it to an ISF file and
        save it to one of the symbol locations."""
        # Check for writability
        filter_string = os.path.join(pdb_name, guid + "-" + str(age))
        for path in symbols.__path__:
            # Store any temporary files created by downloading PDB files
            tmp_files = []
            potential_output_filename = os.path.join(
                path, "windows", filter_string + ".json.xz"
            )
            data_written = False
            try:
                os.makedirs(os.path.dirname(potential_output_filename), exist_ok=True)
                with lzma.open(potential_output_filename, "w") as of:
                    # Once we haven't thrown an error, do the computation
                    filename = pdbconv.PdbRetreiver().retreive_pdb(
                        guid + str(age),
                        file_name=pdb_name,
                        progress_callback=progress_callback,
                    )
                    if filename:
                        url = parse.urlparse(filename, scheme="file")
                        if url.scheme == "file" or len(url.scheme) == 1:
                            tmp_files.append(filename)
                            location = "file:" + request.pathname2url(
                                os.path.abspath(tmp_files[-1])
                            )
                        else:
                            location = filename
                        json_output = pdbconv.PdbReader(
                            context, location, pdb_name, progress_callback
                        ).get_json()
                        of.write(
                            bytes(
                                json.dumps(json_output, indent=2, sort_keys=True),
                                "utf-8",
                            )
                        )
                        # After we've successfully written it out, record the fact so we don't clear it out
                        data_written = True
                    else:
                        vollog.warning(
                            "Symbol file could not be downloaded from remote server"
                            + (" " * 100)
                        )
                break
            except PermissionError:
                vollog.warning(
                    "Cannot write necessary symbol file, please check permissions on {}".format(
                        potential_output_filename
                    )
                )
                continue
            finally:
                # If something else failed, removed the symbol file so we don't pick it up in the future
                if not data_written and os.path.exists(potential_output_filename):
                    os.remove(potential_output_filename)
                # Clear out all the temporary file if we constructed one
                for filename in tmp_files:
                    try:
                        os.remove(filename)
                    except PermissionError:
                        vollog.warning(
                            f"Temporary file could not be removed: {filename}"
                        )
        else:
            vollog.warning(
                "Cannot write downloaded symbols, please add the appropriate symbols"
                " or add/modify a symbols directory that is writable"
            )

    @classmethod
    def pdbname_scan(
        cls,
        ctx: interfaces.context.ContextInterface,
        layer_name: str,
        page_size: int,
        pdb_names: List[bytes],
        progress_callback: constants.ProgressCallback = None,
        start: Optional[int] = None,
        end: Optional[int] = None,
        maximum_invalid_count: int = 100,
    ) -> Generator[Dict[str, Optional[Union[bytes, str, int]]], None, None]:
        """Scans through `layer_name` at `ctx` looking for RSDS headers that
        indicate one of four common pdb kernel names (as listed in
        `self.pdb_names`) and returns the tuple (GUID, age, pdb_name,
        signature_offset, mz_offset)

        .. note:: This is automagical and therefore not guaranteed to provide correct results.

        The UI should always provide the user an opportunity to specify the
        appropriate types and PDB values themselves
        Args:
            layer_name: The layer name to scan
            page_size: Size of page constant
            pdb_names: List of pdb names to scan
            progress_callback: Means of providing the user with feedback during long processes
            start: Start address to start scanning from the pdb_names
            end: Minimum address to scan the pdb_names
            maximum_invalid_count: Amount of pages that can be invalid during scanning before aborting signature search
        """
        min_pfn = 0

        if start is None:
            start = ctx.layers[layer_name].minimum_address
        if end is None:
            end = ctx.layers[layer_name].maximum_address

        for GUID, age, pdb_name, signature_offset in ctx.layers[layer_name].scan(
            ctx,
            PdbSignatureScanner(pdb_names),
            progress_callback=progress_callback,
            sections=[(start, end - start)],
        ):
            mz_offset = None
            sig_pfn = signature_offset // page_size
            current_invalid_counter = 0

            for i in range(sig_pfn, min_pfn, -1):
                if current_invalid_counter > maximum_invalid_count:
                    break

                if not ctx.layers[layer_name].is_valid(i * page_size, 2):
                    current_invalid_counter += 1
                    continue

                data = ctx.layers[layer_name].read(i * page_size, 2)
                if data == b"MZ":
                    mz_offset = i * page_size
                    break
            min_pfn = sig_pfn

            yield {
                "GUID": GUID,
                "age": age,
                "pdb_name": str(pdb_name, "utf-8"),
                "signature_offset": signature_offset,
                "mz_offset": mz_offset,
            }

    @classmethod
    def symbol_table_from_pdb(
        cls,
        context: interfaces.context.ContextInterface,
        config_path: str,
        layer_name: str,
        pdb_name: str,
        module_offset: int = None,
        module_size: int = None,
    ) -> str:
        """Creates symbol table for a module in the specified layer_name.

        Searches the memory section of the loaded module for its PDB GUID
        and loads the associated symbol table into the symbol space.

        Args:
            context: The context to retrieve required elements (layers, symbol tables) from
            config_path: The config path where to find symbol files
            layer_name: The name of the layer on which to operate
            module_offset: This memory dump's module image offset
            module_size: The size of the module for this dump

        Returns:
            The name of the constructed and loaded symbol table
        """
        _, symbol_table_name = cls._modtable_from_pdb(
            context, config_path, layer_name, pdb_name, module_offset, module_size
        )
        return symbol_table_name

    @classmethod
    def _modtable_from_pdb(
        cls,
        context: interfaces.context.ContextInterface,
        config_path: str,
        layer_name: str,
        pdb_name: str,
        module_offset: int = None,
        module_size: int = None,
        create_module: bool = False,
    ) -> Tuple[Optional[str], Optional[str]]:
        if module_offset is None:
            module_offset = context.layers[layer_name].minimum_address
        if module_size is None:
            module_size = context.layers[layer_name].maximum_address - module_offset

        guids = list(
            cls.pdbname_scan(
                context,
                layer_name,
                context.layers[layer_name].page_size,
                [bytes(pdb_name, "latin-1")],
                start=module_offset,
                end=module_offset + module_size,
            )
        )

        if not guids:
            raise exceptions.VolatilityException(
                f"Did not find GUID of {pdb_name} in module @ 0x{module_offset:x}!"
            )

        guid = guids[0]

        vollog.debug(f"Found {guid['pdb_name']}: {guid['GUID']}-{guid['age']}")

        module_name = guid["pdb_name"].replace(".pdb", "")

        symbol_table_name = cls.load_windows_symbol_table(
            context,
            guid["GUID"],
            guid["age"],
            guid["pdb_name"],
            "volatility3.framework.symbols.intermed.IntermediateSymbolTable",
            config_path=config_path,
        )

        new_module_name = None
        if create_module:
            new_module = contexts.Module.create(
                context,
                module_name,
                layer_name,
                offset=guid["mz_offset"],
                symbol_table_name=symbol_table_name,
            )
            new_module_name = new_module.name

        return new_module_name, symbol_table_name

    @classmethod
    def module_from_pdb(
        cls,
        context: interfaces.context.ContextInterface,
        config_path: str,
        layer_name: str,
        pdb_name: str,
        module_offset: int = None,
        module_size: int = None,
    ) -> str:
        """Creates a module in the specified layer_name based on a pdb name.

        Searches the memory section of the loaded module for its PDB GUID
        and loads the associated symbol table into the symbol space.

        Args:
            context: The context to retrieve required elements (layers, symbol tables) from
            config_path: The config path where to find symbol files
            layer_name: The name of the layer on which to operate
            module_offset: This memory dump's module image offset
            module_size: The size of the module for this dump

        Returns:
            The name of the constructed and loaded symbol table
        """

        module_name, _ = cls._modtable_from_pdb(
            context,
            config_path,
            layer_name,
            pdb_name,
            module_offset,
            module_size,
            create_module=True,
        )

        return module_name


class PdbSignatureScanner(interfaces.layers.ScannerInterface):
    """A :class:`~volatility3.framework.interfaces.layers.ScannerInterface`
    based scanner use to identify Windows PDB records.

    Args:
        pdb_names: A list of bytestrings, used to match pdb signatures against the pdb names within the records.

    .. note:: The pdb_names must be a list of byte strings, unicode strs will not match against the data scanned
    """

    overlap = 0x4000
    """The size of overlap needed for the signature to ensure data cannot hide between two scanned chunks"""
    thread_safe = True
    """Determines whether the scanner accesses global variables in a thread safe manner (for use with :mod:`multiprocessing`)"""

    _RSDS_format = struct.Struct("<16BI")

    def __init__(self, pdb_names: List[bytes]) -> None:
        super().__init__()
        self._pdb_names = pdb_names

    def __call__(
        self, data: bytes, data_offset: int
    ) -> Generator[Tuple[str, Any, bytes, int], None, None]:
        pattern = (
            b"RSDS"
            + (b"." * self._RSDS_format.size)
            + b"("
            + b"|".join([re.escape(x) for x in self._pdb_names])
            + b")\x00"
        )
        for match in re.finditer(pattern, data, flags=re.DOTALL):
            pdb_name = data[
                match.start(0)
                + 4
                + self._RSDS_format.size : match.start(0)
                + len(match.group())
                - 1
            ]
            if pdb_name in self._pdb_names:
                ## this ordering is intentional due to mixed endianness in the GUID
                (
                    g3,
                    g2,
                    g1,
                    g0,
                    g5,
                    g4,
                    g7,
                    g6,
                    g8,
                    g9,
                    ga,
                    gb,
                    gc,
                    gd,
                    ge,
                    gf,
                    a,
                ) = self._RSDS_format.unpack(
                    data[
                        match.start(0) + 4 : match.start(0) + 4 + self._RSDS_format.size
                    ]
                )

                guid = (16 * "{:02X}").format(
                    g0, g1, g2, g3, g4, g5, g6, g7, g8, g9, ga, gb, gc, gd, ge, gf
                )
                if match.start(0) < self.chunk_size:
                    yield (guid, a, pdb_name, data_offset + match.start(0))
