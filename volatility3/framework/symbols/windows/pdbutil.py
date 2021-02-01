# This file is Copyright 2020 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

import binascii
import json
import logging
import lzma
import os
import struct
from typing import Any, Dict, Generator, List, Optional, Tuple, Union
from urllib import request

from volatility3 import symbols
from volatility3.framework import constants, interfaces
from volatility3.framework.configuration.requirements import SymbolTableRequirement
from volatility3.framework.symbols import intermed
from volatility3.framework.symbols.windows import pdbconv

vollog = logging.getLogger(__name__)


class PDBUtility:
    """Class to handle and manage all getting symbols based on MZ header"""

    @classmethod
    def symbol_table_from_offset(
            cls,
            context: interfaces.context.ContextInterface,
            layer_name: str,
            offset: int,
            symbol_table_class: str = "volatility3.framework.symbols.intermed.IntermediateSymbolTable",
            config_path: str = None,
            progress_callback: constants.ProgressCallback = None) -> Optional[str]:
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
            return None
        guid, age, pdb_name = result
        if config_path is None:
            config_path = interfaces.configuration.path_join('pdbutility', pdb_name.replace('.', '_'))

        return cls.load_windows_symbol_table(context, guid, age, pdb_name, symbol_table_class, config_path,
                                             progress_callback)

    @classmethod
    def load_windows_symbol_table(cls,
                                  context: interfaces.context.ContextInterface,
                                  guid: str,
                                  age: int,
                                  pdb_name: str,
                                  symbol_table_class: str,
                                  config_path: str = 'pdbutility',
                                  progress_callback: constants.ProgressCallback = None):
        """Loads (downlading if necessary) a windows symbol table"""

        filter_string = os.path.join(pdb_name.strip('\x00'), guid.upper() + "-" + str(age))

        isf_path = False
        # Take the first result of search for the intermediate file
        for value in intermed.IntermediateSymbolTable.file_symbol_url("windows", filter_string):
            isf_path = value
            break
        else:
            # If none are found, attempt to download the pdb, convert it and try again
            cls.download_pdb_isf(context, guid.upper(), age, pdb_name, progress_callback)
            # Try again
            for value in intermed.IntermediateSymbolTable.file_symbol_url("windows", filter_string):
                isf_path = value
                break

        if not isf_path:
            vollog.debug("Required symbol library path not found: {}".format(filter_string))
            return None

        vollog.debug("Using symbol library: {}".format(filter_string))

        # Set the discovered options
        join = interfaces.configuration.path_join
        context.config[join(config_path, "class")] = symbol_table_class
        context.config[join(config_path, "isf_url")] = isf_path
        parent_config_path = interfaces.configuration.parent_path(config_path)
        requirement_name = interfaces.configuration.path_head(config_path)

        # Construct the appropriate symbol table
        requirement = SymbolTableRequirement(name = requirement_name, description = "PDBUtility generated symbol table")
        requirement.construct(context, parent_config_path)
        return context.config[config_path]

    @classmethod
    def get_guid_from_mz(cls, context: interfaces.context.ContextInterface, layer_name: str,
                         offset: int) -> Optional[Tuple[str, int, str]]:
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
            vollog.error("Get_guid_from_mz requires the following python module: pefile")
            return None

        layer = context.layers[layer_name]
        mz_sig = layer.read(offset, 2)

        # Check it is actually the MZ header
        if mz_sig != b"MZ":
            return None

        nt_header_start = ord(layer.read(offset + 0x3C, 1))
        optional_header_size = struct.unpack('<H', layer.read(offset + nt_header_start + 0x14, 2))[0]
        # Just enough to tell us the max size
        pe_header = layer.read(offset, nt_header_start + 0x16 + optional_header_size)
        pe_data = pefile.PE(data = pe_header)
        max_size = pe_data.OPTIONAL_HEADER.SizeOfImage

        # Proper data
        virtual_data = layer.read(offset, max_size)
        pe_data = pefile.PE(data = virtual_data)

        # De-virtualize the memory
        sizeofHdrs = pe_data.OPTIONAL_HEADER.SizeOfHeaders
        physical_data = virtual_data[:sizeofHdrs]
        # Might need to put them in order by PointerToRawData just validate they are in order
        for sect in pe_data.sections:
            physical_data += virtual_data[sect.VirtualAddress:sect.VirtualAddress + sect.SizeOfRawData]

        pe_data = pefile.PE(data = physical_data)

        if not hasattr(pe_data, 'DIRECTORY_ENTRY_DEBUG') or not len(pe_data.DIRECTORY_ENTRY_DEBUG):
            return None

        # Swap the Pointer with the Address since the de-virtualization doesn't apply to the fields
        debug_entry = None
        for index in range(len(pe_data.DIRECTORY_ENTRY_DEBUG)):
            if pe_data.DIRECTORY_ENTRY_DEBUG[index].struct.Type == 2:
                debug_data = pe_data.DIRECTORY_ENTRY_DEBUG[index]
                pe_data.set_dword_at_offset(debug_data.struct.get_field_absolute_offset('AddressOfRawData'),
                                            debug_data.struct.PointerToRawData)
                pe_data.full_load()
                debug_entry = pe_data.DIRECTORY_ENTRY_DEBUG[index].entry

        if debug_entry is None:
            return None

        pdb_name = debug_entry.PdbFileName.decode("utf-8").strip('\x00')
        age = debug_entry.Age
        guid = "{:x}{:x}{:x}{}".format(debug_entry.Signature_Data1, debug_entry.Signature_Data2,
                                       debug_entry.Signature_Data3,
                                       binascii.hexlify(debug_entry.Signature_Data4).decode('utf-8'))
        return guid, age, pdb_name

    @classmethod
    def download_pdb_isf(cls,
                         context: interfaces.context.ContextInterface,
                         guid: str,
                         age: int,
                         pdb_name: str,
                         progress_callback: constants.ProgressCallback = None) -> None:
        """Attempts to download the PDB file, convert it to an ISF file and
        save it to one of the symbol locations."""
        # Check for writability
        filter_string = os.path.join(pdb_name, guid + "-" + str(age))
        for path in symbols.__path__:

            # Store any temporary files created by downloading PDB files
            tmp_files = []
            potential_output_filename = os.path.join(path, "windows", filter_string + ".json.xz")
            data_written = False
            try:
                os.makedirs(os.path.dirname(potential_output_filename), exist_ok = True)
                with lzma.open(potential_output_filename, "w") as of:
                    # Once we haven't thrown an error, do the computation
                    filename = pdbconv.PdbRetreiver().retreive_pdb(guid + str(age),
                                                                   file_name = pdb_name,
                                                                   progress_callback = progress_callback)
                    if filename:
                        tmp_files.append(filename)
                        location = "file:" + request.pathname2url(tmp_files[-1])
                        json_output = pdbconv.PdbReader(context, location, pdb_name, progress_callback).get_json()
                        of.write(bytes(json.dumps(json_output, indent = 2, sort_keys = True), 'utf-8'))
                        # After we've successfully written it out, record the fact so we don't clear it out
                        data_written = True
                    else:
                        vollog.warning("Symbol file could not be found on remote server" + (" " * 100))
                break
            except PermissionError:
                vollog.warning("Cannot write necessary symbol file, please check permissions on {}".format(
                    potential_output_filename))
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
                        vollog.warning("Temporary file could not be removed: {}".format(filename))
        else:
            vollog.warning("Cannot write downloaded symbols, please add the appropriate symbols"
                           " or add/modify a symbols directory that is writable")

    @classmethod
    def pdbname_scan(cls,
                     ctx: interfaces.context.ContextInterface,
                     layer_name: str,
                     page_size: int,
                     pdb_names: List[bytes],
                     progress_callback: constants.ProgressCallback = None,
                     start: Optional[int] = None,
                     end: Optional[int] = None) -> Generator[Dict[str, Optional[Union[bytes, str, int]]], None, None]:
        """Scans through `layer_name` at `ctx` looking for RSDS headers that
        indicate one of four common pdb kernel names (as listed in
        `self.pdb_names`) and returns the tuple (GUID, age, pdb_name,
        signature_offset, mz_offset)

        .. note:: This is automagical and therefore not guaranteed to provide correct results.

        The UI should always provide the user an opportunity to specify the
        appropriate types and PDB values themselves
        """
        min_pfn = 0

        if start is None:
            start = ctx.layers[layer_name].minimum_address
        if end is None:
            end = ctx.layers[layer_name].maximum_address

        for (GUID, age, pdb_name,
             signature_offset) in ctx.layers[layer_name].scan(ctx,
                                                              PdbSignatureScanner(pdb_names),
                                                              progress_callback = progress_callback,
                                                              sections = [(start, end - start)]):
            mz_offset = None
            sig_pfn = signature_offset // page_size

            for i in range(sig_pfn, min_pfn, -1):
                if not ctx.layers[layer_name].is_valid(i * page_size, 2):
                    break

                data = ctx.layers[layer_name].read(i * page_size, 2)
                if data == b'MZ':
                    mz_offset = i * page_size
                    break
            min_pfn = sig_pfn

            yield {
                'GUID': GUID,
                'age': age,
                'pdb_name': str(pdb_name, "utf-8"),
                'signature_offset': signature_offset,
                'mz_offset': mz_offset
            }


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

    def __call__(self, data: bytes, data_offset: int) -> Generator[Tuple[str, Any, bytes, int], None, None]:
        sig = data.find(b"RSDS")
        while sig >= 0:
            null = data.find(b'\0', sig + 4 + self._RSDS_format.size)
            if null > -1:
                if (null - sig - self._RSDS_format.size) <= 100:
                    name_offset = sig + 4 + self._RSDS_format.size
                    pdb_name = data[name_offset:null]
                    if pdb_name in self._pdb_names:

                        ## this ordering is intentional due to mixed endianness in the GUID
                        (g3, g2, g1, g0, g5, g4, g7, g6, g8, g9, ga, gb, gc, gd, ge, gf, a) = \
                            self._RSDS_format.unpack(data[sig + 4:name_offset])

                        guid = (16 * '{:02X}').format(g0, g1, g2, g3, g4, g5, g6, g7, g8, g9, ga, gb, gc, gd, ge, gf)
                        if sig < self.chunk_size:
                            yield (guid, a, pdb_name, data_offset + sig)
            sig = data.find(b"RSDS", sig + 1)
