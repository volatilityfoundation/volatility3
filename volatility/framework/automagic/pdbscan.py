"""A module for scanning translation layers looking for Windows PDB records from loaded PE files.

    This module contains a standalone scanner, and also a :class:`~volatility.framework.interfaces.layers.ScannerInterface`
    based scanner for use within the framework by calling :func:`~volatility.framework.interfaces.layers.DataLayerInterface.scan`.
"""

import logging
import math
import os
import struct

from volatility.framework import exceptions, layers
from volatility.framework.layers import scanners
from volatility.framework.symbols import native

if __name__ == "__main__":
    import sys

    sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(__file__)))))

from volatility.framework import interfaces

vollog = logging.getLogger(__name__)
PAGE_SIZE = 0x1000


class PdbSigantureScanner(interfaces.layers.ScannerInterface):
    """A :class:`~volatility.framework.interfaces.layers.ScannerInterface` based scanner use to identify Windows PDB records

    :param pdb_names: A list of bytestrings, used to match pdb signatures against the pdb names within the records.
    :type pdb_names: A list of :class:`bytestring` objects

    .. note:: The pdb_names must be a list of byte strings, unicode strs will not match against the data scanned
    """
    overlap = 0x4000
    """The size of overlap needed for the signature to ensure data cannot hide between two scanned chunks"""
    thread_safe = True
    """Determines whether the scanner accesses global variables in a thread safe manner (for use with :mod:`multiprocessing`)"""

    _RSDS_format = struct.Struct("<16BI")

    def __init__(self, pdb_names):
        super().__init__()
        self._pdb_names = pdb_names

    def __call__(self, data, data_offset):
        sig = data.find(b"RSDS")
        while sig >= 0:
            null = data.find(b'\0', sig + 4 + self._RSDS_format.size)
            if null > -1:
                if (null - sig - self._RSDS_format.size) <= 100:
                    name_offset = sig + 4 + self._RSDS_format.size
                    pdb_name = data[name_offset:null]
                    if pdb_name in self._pdb_names:

                        ## thie ordering is intentional due to mixed endianness in the GUID
                        (g3, g2, g1, g0, g5, g4, g7, g6, g8, g9, ga, gb, gc, gd, ge, gf, a) = \
                            self._RSDS_format.unpack(data[sig + 4:name_offset])

                        GUID = (16 * '{:02X}').format(g0, g1, g2, g3, g4, g5, g6, g7, g8, g9, ga, gb, gc, gd, ge, gf)
                        yield (GUID, a, pdb_name, data_offset + sig)
            sig = data.find(b"RSDS", sig + 1)


def scan(ctx, layer_name, progress_callback = None, start = None, end = None):
    """Scans through `layer_name` at `ctx` looking for RSDS headers that indicate one of four common pdb kernel names
       (as listed in `self.pdb_names`) and returns the tuple (GUID, age, pdb_name, signature_offset, mz_offset)

       .. note:: This is automagical and therefore not guaranteed to provide correct results.

       The UI should always provide the user an opportunity to specify the
       appropriate types and PDB values themselves
    """
    results = []
    min_pfn = 0
    pdb_names = [
        b"ntkrnlmp.pdb",
        b"ntkrnlpa.pdb",
        b"ntkrpamp.pdb",
        b"ntoskrnl.pdb",
    ]

    for (GUID, age, pdb_name, signature_offset) in ctx.memory[layer_name].scan(ctx, PdbSigantureScanner(pdb_names),
                                                                               progress_callback = progress_callback,
                                                                               min_address = start,
                                                                               max_address = end):
        mz_offset = None
        sig_pfn = signature_offset // PAGE_SIZE

        for i in range(sig_pfn, min_pfn, -1):
            if not ctx.memory[layer_name].is_valid(i * PAGE_SIZE, 2):
                break

            data = ctx.memory[layer_name].read(i * PAGE_SIZE, 2)
            if data == b'MZ':
                mz_offset = i * PAGE_SIZE
                break
        min_pfn = sig_pfn

        results.append({'GUID': GUID,
                        'age': age,
                        'pdb_name': str(pdb_name, "utf-8"),
                        'signature_offset': signature_offset,
                        'mz_offset': mz_offset})

    return results


class KernelPDBScanner(interfaces.automagic.AutomagicInterface):
    """An Automagic object that looks for all Intel translation layers and scans each of them for a pdb signature.
    When found, a search for a corresponding Intermediate Format data file is carried out and if found an appropriate
    symbol space is automatically loaded.

    Once a specific kernel PDB signature has been found, a virtual address for the loaded kernel is determined
    by one of two methods.  The first method assumes a specific mapping from the kernel's physical address to its
    virtual address (typically the kernel is loaded at its physical location plus a specific offset).  The second method
    searches for a particular structure that lists the kernel module's virtual address, its size (not checked) and the
    module's name.  This value is then used if one was not found using the previous method.
    """
    priority = 30

    # Make sure uncompressed/outside-framework takes precedence, so users can overload.
    prefixes = [os.path.join("..", "..", "..", "symbols", "windows"),
                os.path.join("..", "..", "symbols", "windows")]
    """Provides a list of prefixes that are searched when locating Intermediate Format data files"""
    suffixes = ['.json', '.json.xz']
    """Provides a list of supported suffixes for Intermediate Format data files"""

    def __init__(self):
        super().__init__()
        self.valid_kernels = []

    def recurse_pdb_finder(self, context, config_path, requirement, progress_callback = None):
        """Traverses the requirement tree, rooted at `requirement` looking for virtual layers that might contain a windows PDB.

        Returns a list of possible kernel locations in the physical memory

        :param context: The context in which the `requirement` lives
        :type context: ~volatility.framework.interfaces.context.ContextInterface
        :param config_path: The path within the `context` for the `requirement`'s configuration variables
        :type config_path: str
        :param requirement: The root of the requirement tree to search for :class:~`volatility.framework.interfaces.layers.TranslationLayerRequirement` objects to scan
        :type requirement: ~volatility.framework.interfaces.configuration.RequirementInterface
        :return: A list of (layer_name, scan_results)
        """
        sub_config_path = interfaces.configuration.path_join(config_path, requirement.name)
        results = {}
        if isinstance(requirement, interfaces.configuration.TranslationLayerRequirement):
            # Check for symbols in this layer
            # FIXME: optionally allow a full (slow) scan
            # FIXME: Determine the physical layer no matter the virtual layer
            virtual_layer_name = context.config.get(sub_config_path, None)
            layer_name = context.config.get(interfaces.configuration.path_join(sub_config_path, "memory_layer"), None)
            if layer_name:
                results = {virtual_layer_name: scan(context, layer_name, progress_callback = progress_callback)}
        else:
            for subreq in requirement.requirements.values():
                results.update(self.recurse_pdb_finder(context, sub_config_path, subreq))
        return results

    def recurse_symbol_requirements(self, context, config_path, requirement):
        """Determines if there is actually an unfulfilled symbol requirement waiting

        This ensures we do not carry out an expensive search when there is no requirement for a particular symbol table.

        :param context: Context on which to operate
        :type context: ~volatility.framework.interfaces.context.ContextInterface
        :param config_path: Configuration path of the top-level requirement
        :type config_path: str
        :param requirement: Top-level requirement whose subrequirements will all be searched
        :type requirement: ~volatility.framework.interfaces.configuration.RequirementInterface
        :return: A list of tuples containing the config_path, sub_config_path and requirement identifying the SymbolRequirements
        """
        sub_config_path = interfaces.configuration.path_join(config_path, requirement.name)
        results = []
        if isinstance(requirement, interfaces.configuration.SymbolRequirement):
            # TODO: check if this is a windows symbol requirement, otherwise ignore it
            if not requirement.validate(context, config_path):
                results.append((config_path, sub_config_path, requirement))
        else:
            for subreq in requirement.requirements.values():
                results += self.recurse_symbol_requirements(context, sub_config_path, subreq)
        return results

    def recurse_symbol_fulfiller(self, context):
        """Fulfills the SymbolRequirements in `self._symbol_requirements` found by the `recurse_symbol_requirements`.

        This pass will construct any requirements that may need it in the context it was passed

        :param context: Context on which to operate
        :type context: ~volatility.framework.interfaces.context.ContextInterface
        """
        for config_path, sub_config_path, requirement in self._symbol_requirements:
            # TODO: Potentially think about multiple symbol requirements in both the same and different levels of the requirement tree
            # TODO: Consider whether a single found kernel can fulfill multiple requirements
            suffix = ".json"
            if self.valid_kernels:
                # TODO: Check that the symbols for this kernel will fulfill the requirement
                kernel = None
                for virtual_layer in self.valid_kernels:
                    _kvo, kernel = self.valid_kernels[virtual_layer]
                    # Check user symbol directory first, then fallback to the framework's library to allow for overloading
                    midfix = os.path.join(kernel['pdb_name'], kernel['GUID'] + "-" + str(kernel['age']))
                    idd_path = None
                    for prefix in self.prefixes:
                        if not os.path.isabs(prefix):
                            prefix = os.path.abspath(os.path.join(__file__, prefix))
                        for suffix in self.suffixes:
                            if os.path.exists(os.path.join(prefix, midfix + suffix)):
                                idd_path = "file://" + os.path.abspath(os.path.join(prefix, midfix + suffix))
                    if idd_path:
                        vollog.debug("Using symbol library: {}".format(midfix))
                        clazz = "volatility.framework.symbols.windows.WindowsKernelIntermedSymbols"
                        # Set the discovered options
                        context.config[interfaces.configuration.path_join(sub_config_path, "class")] = clazz
                        context.config[interfaces.configuration.path_join(sub_config_path, "idd_filepath")] = idd_path
                        # Construct the appropriate symbol table
                        requirement.construct(context, config_path)
                        break
                    else:
                        vollog.debug("Symbol library path not found: {}".format(midfix + suffix))
                else:
                    vollog.debug("No suitable kernel pdb signature found")

    def set_kernel_virtual_offset(self, context):
        """Traverses the requirement tree, looking for kernel_virtual_offset values that may need setting and sets
        it based on the previously identified `valid_kernels`.

        :param context: Context on which to operate and provide the kernel virtual offset
        :type context: ~volatility.framework.interfaces.context.ContextInterface
        """
        for virtual_layer in self.valid_kernels:
            # Sit the virtual offset under the TranslationLayer it applies to
            kvo_path = interfaces.configuration.path_join(context.memory[virtual_layer].config_path,
                                                          'kernel_virtual_offset')
            kvo, kernel = self.valid_kernels[virtual_layer]
            context.config[kvo_path] = kvo
            vollog.debug("Setting kernel_virtual_offset to {}".format(hex(kvo)))

    def determine_valid_kernels(self, context, potential_kernels, progress_callback = None):
        """Runs through the identified potential kernels and verifies their suitability

        This carries out a scan using the pdb_signature scanner on a physical layer.  It uses the
        results of the scan to determine the virtual offset of the kernel.  On early windows implementations
        there is a fixed mapping between the physical and virtual addresses of the kernel.  On more recent versions
        a search is conducted for a structure that will identify the kernel's virtual offset.

        :param context: Context on which to operate
        :type context: ~volatility.framework.interfaces.context.ContextInterface
        :param potential_kernels: Dictionary containing `GUID`, `age`, `pdb_name` and `mz_offset` keys
        :type potential_kernels: dict
        :param progress_callback: Function taking a percentage and optional description to be called during expensive computations to indicate progress
        :type progress_callback: function
        :return: A dictionary of valid kernels
        """
        valid_kernels = {}
        for virtual_layer_name in potential_kernels:
            kernels = potential_kernels[virtual_layer_name]
            virtual_config_path = context.memory[virtual_layer_name].config_path
            if virtual_layer_name and isinstance(context.memory[virtual_layer_name], layers.intel.Intel):
                # TODO: Verify this is a windows image
                vlayer = context.memory[virtual_layer_name]
                physical_layer_name = context.config.get(
                    interfaces.configuration.path_join(vlayer.config_path, 'memory_layer'), None)
                found = False
                kvo_path = interfaces.configuration.path_join(virtual_config_path, 'kernel_virtual_offset')
                for kernel in kernels:
                    # It seems the kernel is loaded at a fixed mapping (presumably because the memory manager hasn't started yet)
                    if kernel['mz_offset'] is None:
                        # Rule out kernels that couldn't find a suitable MZ header
                        continue
                    if vlayer.bits_per_register == 64:
                        kvo = kernel['mz_offset'] + (31 << int(math.ceil(math.log2(vlayer.maximum_address + 1)) - 5))
                    else:
                        kvo = kernel['mz_offset'] + (1 << (vlayer.bits_per_register - 1))
                    try:
                        kvp = context.memory[virtual_layer_name].mapping(kvo, 0)
                        if (any([(p == kernel['mz_offset'] and l == physical_layer_name) for (_, p, _, l) in
                                 kvp])):
                            valid_kernels[virtual_layer_name] = (kvo, kernel)
                            # Sit the virtual offset under the TranslationLayer it applies to
                            context.config[kvo_path] = kvo
                            vollog.debug("Setting kernel_virtual_offset to {}".format(hex(kvo)))
                            break
                        else:
                            vollog.debug(
                                "Potential kernel_virtual_offset did not map to expected location: {}".format(
                                    hex(kvo)))
                    except exceptions.PagedInvalidAddressException:
                        vollog.debug("Potential kernel_virtual_offset caused a page fault: {}".format(hex(kvo)))
                else:
                    vollog.debug("Kernel base randomized, searching layer for base address offset")
                    # If we're here, chances are high we're in a Win10 x64 image with kernel base randomization
                    physical_layer = context.memory[physical_layer_name]
                    # TODO:  On older windows, this might be \WINDOWS\system32\nt rather than \SystemRoot\system32\nt
                    results = physical_layer.scan(context, scanners.BytesScanner(b"\\SystemRoot\\system32\\nt"),
                                                  progress_callback = progress_callback)
                    seen = set()
                    for result in results:
                        # TODO: Identify the specific structure we're finding and document this a bit better
                        pointer = context.object("pdbscan!unsigned long long", offset = (result - 16 - 8),
                                                 layer_name = physical_layer_name)
                        address = pointer & vlayer.address_mask
                        if address in seen:
                            continue
                        seen.add(address)
                        try:
                            potential_mz = vlayer.read(offset = address, length = 2)
                            if potential_mz == b"MZ":
                                subscan = scan(context, virtual_layer_name, start = address, end = address + (1 << 26),
                                               progress_callback = progress_callback)
                                for result in subscan:
                                    valid_kernels[virtual_layer_name] = (address, result)
                                    break
                        except exceptions.PagedInvalidAddressException:
                            # We don't care if we're mapping an address to 0, it's not what we're looking for
                            pass
            if not valid_kernels:
                vollog.warning("No suitable kernel found for layer: {}".format(virtual_layer_name))
        if not valid_kernels:
            vollog.warning("No suitable kernels found during pdbscan")
        return valid_kernels

    def __call__(self, context, config_path, requirement, progress_callback = None):
        # TODO: Check if we really need to search for pdbs
        if "pdbscan" not in context.symbol_space:
            context.symbol_space.append(native.NativeTable("pdbscan", native.std_ctypes))
        self._symbol_requirements = self.recurse_symbol_requirements(context, config_path, requirement)
        if self._symbol_requirements:
            potential_kernels = self.recurse_pdb_finder(context, config_path, requirement, progress_callback)
            self.valid_kernels = self.determine_valid_kernels(context, potential_kernels, progress_callback)
            if self.valid_kernels:
                self.recurse_symbol_fulfiller(context)
                self.set_kernel_virtual_offset(context)
