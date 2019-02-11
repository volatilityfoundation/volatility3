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
"""A module for scanning translation layers looking for Windows PDB records from loaded PE files.

    This module contains a standalone scanner, and also a :class:`~volatility.framework.interfaces.layers.ScannerInterface`
    based scanner for use within the framework by calling :func:`~volatility.framework.interfaces.layers.DataLayerInterface.scan`.
"""

import logging
import math
import os
import struct
from typing import Any, Dict, Generator, Iterable, List, Optional, Set, Tuple, Union

from volatility.framework import constants, exceptions, interfaces, layers
from volatility.framework.configuration import requirements
from volatility.framework.layers import intel, scanners
from volatility.framework.symbols import intermed, native

if __name__ == "__main__":
    import sys

    sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(__file__)))))

vollog = logging.getLogger(__name__)

ValidKernelsType = Dict[str, Tuple[int, Dict[str, Optional[Union[bytes, str, int]]]]]
KernelsType = Iterable[Dict[str, Any]]


class PdbSignatureScanner(interfaces.layers.ScannerInterface):
    """A :class:`~volatility.framework.interfaces.layers.ScannerInterface` based scanner use to identify Windows PDB records

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


def scan(ctx: interfaces.context.ContextInterface,
         layer_name: str,
         page_size: int,
         progress_callback: constants.ProgressCallback = None,
         start: Optional[int] = None,
         end: Optional[int] = None) -> Generator[Dict[str, Optional[Union[bytes, str, int]]], None, None]:
    """Scans through `layer_name` at `ctx` looking for RSDS headers that indicate one of four common pdb kernel names
       (as listed in `self.pdb_names`) and returns the tuple (GUID, age, pdb_name, signature_offset, mz_offset)

       .. note:: This is automagical and therefore not guaranteed to provide correct results.

       The UI should always provide the user an opportunity to specify the
       appropriate types and PDB values themselves
    """
    min_pfn = 0
    pdb_names = [bytes(name + ".pdb", "utf-8") for name in constants.windows.KERNEL_MODULE_NAMES]

    if start is None:
        start = ctx.memory[layer_name].minimum_address
    if end is None:
        end = ctx.memory[layer_name].maximum_address

    for (GUID, age, pdb_name, signature_offset) in ctx.memory[layer_name].scan(
            ctx, PdbSignatureScanner(pdb_names), progress_callback = progress_callback, sections = [(start,
                                                                                                     end - start)]):
        mz_offset = None
        sig_pfn = signature_offset // page_size

        for i in range(sig_pfn, min_pfn, -1):
            if not ctx.memory[layer_name].is_valid(i * page_size, 2):
                break

            data = ctx.memory[layer_name].read(i * page_size, 2)
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


class KernelPDBScanner(interfaces.automagic.AutomagicInterface):
    """Windows symbol loader based on PDB signatures

    An Automagic object that looks for all Intel translation layers and scans each of them for a pdb signature.
    When found, a search for a corresponding Intermediate Format data file is carried out and if found an appropriate
    symbol space is automatically loaded.

    Once a specific kernel PDB signature has been found, a virtual address for the loaded kernel is determined
    by one of two methods.  The first method assumes a specific mapping from the kernel's physical address to its
    virtual address (typically the kernel is loaded at its physical location plus a specific offset).  The second method
    searches for a particular structure that lists the kernel module's virtual address, its size (not checked) and the
    module's name.  This value is then used if one was not found using the previous method.
    """
    priority = 30
    max_pdb_size = 0x400000

    def find_virtual_layers_from_req(self, context: interfaces.context.ContextInterface, config_path: str,
                                     requirement: interfaces.configuration.RequirementInterface) -> List[str]:
        """Traverses the requirement tree, rooted at `requirement` looking for virtual layers that might contain a windows PDB.

        Returns a list of possible layers

        Args:
            context: The context in which the `requirement` lives
            config_path: The path within the `context` for the `requirement`'s configuration variables
            requirement: The root of the requirement tree to search for :class:~`volatility.framework.interfaces.layers.TranslationLayerRequirement` objects to scan
            progress_callback: Means of providing the user with feedback during long processes

        Returns:
            A list of (layer_name, scan_results)
        """
        sub_config_path = interfaces.configuration.path_join(config_path, requirement.name)
        results = []  # type: List[str]
        if isinstance(requirement, requirements.TranslationLayerRequirement):
            # Check for symbols in this layer
            # FIXME: optionally allow a full (slow) scan
            # FIXME: Determine the physical layer no matter the virtual layer
            virtual_layer_name = context.config.get(sub_config_path, None)
            layer_name = context.config.get(interfaces.configuration.path_join(sub_config_path, "memory_layer"), None)
            if layer_name and virtual_layer_name:
                memlayer = context.memory[virtual_layer_name]
                if isinstance(memlayer, intel.Intel):
                    results = [virtual_layer_name]
        else:
            for subreq in requirement.requirements.values():
                results += self.find_virtual_layers_from_req(context, sub_config_path, subreq)
        return results

    def recurse_symbol_fulfiller(self, context: interfaces.context.ContextInterface,
                                 valid_kernels: ValidKernelsType) -> None:
        """Fulfills the SymbolTableRequirements in `self._symbol_requirements` found by the `recurse_symbol_requirements`.

        This pass will construct any requirements that may need it in the context it was passed

        Args:
            context: Context on which to operate
            valid_kernels: A list of offsets where valid kernels have been found
        """
        join = interfaces.configuration.path_join
        for sub_config_path, requirement in self._symbol_requirements:
            # TODO: Potentially think about multiple symbol requirements in both the same and different levels of the requirement tree
            # TODO: Consider whether a single found kernel can fulfill multiple requirements
            if valid_kernels:
                # TODO: Check that the symbols for this kernel will fulfill the requirement
                for virtual_layer in valid_kernels:
                    _kvo, kernel = valid_kernels[virtual_layer]
                    if not isinstance(kernel['pdb_name'], str) or not isinstance(kernel['GUID'], str):
                        raise TypeError("PDB name or GUID not a string value")
                    filter_string = os.path.join(kernel['pdb_name'], kernel['GUID'] + "-" + str(kernel['age']))
                    # Take the first result of search for the intermediate file
                    for value in intermed.IntermediateSymbolTable.file_symbol_url("windows", filter_string):
                        isf_path = value
                        break
                    else:
                        isf_path = ''
                    if isf_path:
                        vollog.debug("Using symbol library: {}".format(filter_string))
                        clazz = "volatility.framework.symbols.windows.WindowsKernelIntermedSymbols"
                        # Set the discovered options
                        context.config[join(sub_config_path, "class")] = clazz
                        context.config[join(sub_config_path, "isf_url")] = isf_path
                        # Construct the appropriate symbol table
                        config_path = interfaces.configuration.parent_path(sub_config_path)
                        if isinstance(requirement, interfaces.configuration.ConstructableRequirementInterface):
                            requirement.construct(context, config_path)
                        break
                    else:
                        vollog.debug("Required symbol library path not found: {}".format(filter_string))
                else:
                    vollog.debug("No suitable kernel pdb signature found")

    def set_kernel_virtual_offset(self, context: interfaces.context.ContextInterface,
                                  valid_kernels: ValidKernelsType) -> None:
        """Traverses the requirement tree, looking for kernel_virtual_offset values that may need setting and sets
        it based on the previously identified `valid_kernels`.

        Args:
            context: Context on which to operate and provide the kernel virtual offset
            valid_kernels: List of valid kernels and offsets
        """
        for virtual_layer in valid_kernels:
            # Set the virtual offset under the TranslationLayer it applies to
            kvo_path = interfaces.configuration.path_join(context.memory[virtual_layer].config_path,
                                                          'kernel_virtual_offset')
            kvo, kernel = valid_kernels[virtual_layer]
            context.config[kvo_path] = kvo
            vollog.debug("Setting kernel_virtual_offset to {}".format(hex(kvo)))

    def get_physical_layer_name(self, context, vlayer):
        return context.config.get(interfaces.configuration.path_join(vlayer.config_path, 'memory_layer'), None)

    def method_fixed_mapping(self,
                             context: interfaces.context.ContextInterface,
                             vlayer: layers.intel.Intel,
                             progress_callback: constants.ProgressCallback = None) -> ValidKernelsType:
        # TODO: Verify this is a windows image
        vollog.debug("Kernel base determination - testing fixed base address")
        valid_kernels = {}
        virtual_layer_name = vlayer.name
        physical_layer_name = self.get_physical_layer_name(context, vlayer)
        kvo_path = interfaces.configuration.path_join(vlayer.config_path, 'kernel_virtual_offset')

        kernels = scan(
            ctx = context,
            layer_name = physical_layer_name,
            page_size = vlayer.page_size,
            progress_callback = progress_callback)
        for kernel in kernels:
            # It seems the kernel is loaded at a fixed mapping (presumably because the memory manager hasn't started yet)
            if kernel['mz_offset'] is None or not isinstance(kernel['mz_offset'], int):
                # Rule out kernels that couldn't find a suitable MZ header
                continue
            if vlayer.bits_per_register == 64:
                kvo = kernel['mz_offset'] + (31 << int(math.ceil(math.log2(vlayer.maximum_address + 1)) - 5))
            else:
                kvo = kernel['mz_offset'] + (1 << (vlayer.bits_per_register - 1))
            try:
                kvp = vlayer.mapping(kvo, 0)
                if (any([(p == kernel['mz_offset'] and layer_name == physical_layer_name)
                         for (_, p, _, layer_name) in kvp])):
                    valid_kernels[virtual_layer_name] = (kvo, kernel)
                    # Sit the virtual offset under the TranslationLayer it applies to
                    context.config[kvo_path] = kvo
                    vollog.debug("Setting kernel_virtual_offset to {}".format(hex(kvo)))
                    break
                else:
                    vollog.debug("Potential kernel_virtual_offset did not map to expected location: {}".format(
                        hex(kvo)))
            except exceptions.InvalidAddressException:
                vollog.debug("Potential kernel_virtual_offset caused a page fault: {}".format(hex(kvo)))
        return valid_kernels

    def method_module_offset(self,
                             context: interfaces.context.ContextInterface,
                             vlayer: layers.intel.Intel,
                             progress_callback: constants.ProgressCallback = None) -> ValidKernelsType:
        """Method for finding a suitable kernel offset based on a module table"""
        vollog.debug("Kernel base determination - searching layer module list structure")
        valid_kernels = {}  # type: ValidKernelsType
        # If we're here, chances are high we're in a Win10 x64 image with kernel base randomization
        virtual_layer_name = vlayer.name
        physical_layer_name = self.get_physical_layer_name(context, vlayer)
        physical_layer = context.memory[physical_layer_name]
        # TODO:  On older windows, this might be \WINDOWS\system32\nt rather than \SystemRoot\system32\nt
        results = physical_layer.scan(
            context, scanners.BytesScanner(b"\\SystemRoot\\system32\\nt"), progress_callback = progress_callback)
        seen = set()  # type: Set[int]
        # Because this will launch a scan of the virtual layer, we want to be careful
        for result in results:
            # TODO: Identify the specific structure we're finding and document this a bit better
            pointer = context.object(
                "pdbscan!unsigned long long",
                offset = (result - 16 - int(vlayer.bits_per_register / 8)),
                layer_name = physical_layer_name)
            address = pointer & vlayer.address_mask
            if address in seen:
                continue
            seen.add(address)

            valid_kernels = self.check_kernel_offset(context, vlayer, address, progress_callback)

            if valid_kernels:
                break
        return valid_kernels

    def method_kdbg_offset(self,
                           context: interfaces.context.ContextInterface,
                           vlayer: layers.intel.Intel,
                           progress_callback: constants.ProgressCallback = None) -> ValidKernelsType:
        vollog.debug("Kernel base determination - using KDBG structure for kernel offset")
        valid_kernels = {}  # type: ValidKernelsType
        physical_layer_name = self.get_physical_layer_name(context, vlayer)
        physical_layer = context.memory[physical_layer_name]
        results = physical_layer.scan(context, scanners.BytesScanner(b"KDBG"), progress_callback = progress_callback)

        seen = set()  # type: Set[int]
        for result in results:
            # TODO: Identify the specific structure we're finding and document this a bit better
            pointer = context.object(
                "pdbscan!unsigned long long", offset = result + 8, layer_name = physical_layer_name)
            address = pointer & vlayer.address_mask
            if address in seen:
                continue
            seen.add(address)

            valid_kernels = self.check_kernel_offset(context, vlayer, address, progress_callback)

            if valid_kernels:
                break

        return valid_kernels

    def check_kernel_offset(self,
                            context: interfaces.context.ContextInterface,
                            vlayer: layers.intel.Intel,
                            address: int,
                            progress_callback: constants.ProgressCallback = None) -> ValidKernelsType:
        """Scans a virtual address """
        # Scan a few megs of the virtual space at the location to see if they're potential kernels

        valid_kernels = {}  # type: ValidKernelsType

        virtual_layer_name = vlayer.name
        try:
            if vlayer.read(address, 0x2) == b'MZ':
                res = list(
                    scan(
                        ctx = context,
                        layer_name = vlayer.name,
                        page_size = vlayer.page_size,
                        progress_callback = progress_callback,
                        start = address,
                        end = address + self.max_pdb_size))
                if res:
                    valid_kernels[virtual_layer_name] = (address, res[0])
        except exceptions.InvalidAddressException:
            pass
        return valid_kernels

    # List of methods to be run, in order, to determine the valid kernels
    methods = [method_kdbg_offset, method_module_offset, method_fixed_mapping]

    def determine_valid_kernels(self,
                                context: interfaces.context.ContextInterface,
                                potential_layers: List[str],
                                progress_callback: constants.ProgressCallback = None) -> ValidKernelsType:
        """Runs through the identified potential kernels and verifies their suitability

        This carries out a scan using the pdb_signature scanner on a physical layer.  It uses the
        results of the scan to determine the virtual offset of the kernel.  On early windows implementations
        there is a fixed mapping between the physical and virtual addresses of the kernel.  On more recent versions
        a search is conducted for a structure that will identify the kernel's virtual offset.

        Args:
            context: Context on which to operate
            potential_kernels: Dictionary containing `GUID`, `age`, `pdb_name` and `mz_offset` keys
            progress_callback: Function taking a percentage and optional description to be called during expensive computations to indicate progress

        Returns:
            A dictionary of valid kernels
        """
        valid_kernels = {}  # type: ValidKernelsType
        for virtual_layer_name in potential_layers:
            vlayer = context.memory.get(virtual_layer_name, None)
            if isinstance(vlayer, layers.intel.Intel):
                for method in self.methods:
                    valid_kernels = method(self, context, vlayer, progress_callback)
                    if valid_kernels:
                        break
        if not valid_kernels:
            vollog.info("No suitable kernels found during pdbscan")
        return valid_kernels

    def __call__(self,
                 context: interfaces.context.ContextInterface,
                 config_path: str,
                 requirement: interfaces.configuration.RequirementInterface,
                 progress_callback: constants.ProgressCallback = None) -> None:
        if requirement.unsatisfied(context, config_path):
            if "pdbscan" not in context.symbol_space:
                context.symbol_space.append(native.NativeTable("pdbscan", native.std_ctypes))
            # TODO: check if this is a windows symbol requirement, otherwise ignore it
            self._symbol_requirements = self.find_requirements(context, config_path, requirement,
                                                               requirements.SymbolTableRequirement)
            potential_layers = self.find_virtual_layers_from_req(
                context = context, config_path = config_path, requirement = requirement)
            for sub_config_path, symbol_req in self._symbol_requirements:
                parent_path = interfaces.configuration.parent_path(sub_config_path)
                if symbol_req.unsatisfied(context, parent_path):
                    valid_kernels = self.determine_valid_kernels(context, potential_layers, progress_callback)
                    if valid_kernels:
                        self.recurse_symbol_fulfiller(context, valid_kernels)
                        self.set_kernel_virtual_offset(context, valid_kernels)
