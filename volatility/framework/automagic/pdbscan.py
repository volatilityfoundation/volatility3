# pdbscan.py -- Scan Volatility Layers for Windows kernel PDB signatures
#

import logging
import math
import os
import struct

from volatility.framework import configuration, exceptions, layers

if __name__ == "__main__":
    import sys

    sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(__file__)))))

from volatility.framework import interfaces

vollog = logging.getLogger(__name__)
PAGE_SIZE = 0x1000


class PdbSigantureScanner(interfaces.layers.ScannerInterface):
    overlap = 0x4000

    _RSDS_format = struct.Struct("<16BI")

    def __init__(self, pdb_names):
        super().__init__()
        self._pdb_names = pdb_names

    def __call__(self, data, data_offset):
        sig = data.find(b"RSDS")
        pdb_hits = []
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


def scan(ctx, layer_name):
    """Scans through layer_name at context and returns the tuple
       (GUID, age, pdb_name, signature_offset, mz_offset)

       Note that this is automagical and therefore not guaranteed to provide
       correct results.

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
                                                                               progress_callback = progress_callback):
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


def progress_callback(progress):
    print("\rProgress: ", progress, "     ", end = '')


class KernelPDBScanner(interfaces.automagic.AutomagicInterface):
    """Looks for all Intel address spaces and attempts to identify the PDB guid required for the space"""
    priority = 30

    # Make sure uncompressed/outside-framework takes precedence, so users can overload.
    prefixes = [os.path.join(os.path.dirname(__file__), "..", "..", "symbols", "windows"),
                os.path.join(os.path.dirname(__file__), "..", "symbols", "windows")]
    suffixes = ['.json', '.json.xz']

    def __init__(self):
        super().__init__()
        self.potential_kernels = []

    def recurse_pdb_finder(self, context, config_path, requirement):
        """Traverses the requirement tree looking for virtual layers that might contain a windows PDB

           Returns a list of possible kernel locations in the physical memory
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
                results = {virtual_layer_name: scan(context, layer_name)}
        else:
            for subreq in requirement.requirements.values():
                results.update(self.recurse_pdb_finder(context, sub_config_path, subreq))
        return results

    def recurse_symbol_fulfiller(self, context, config_path, requirement):
        """Traverses the requirement tree looking to populate Symbol requirements based on the result of the pdb_finder

           This pass will construct any requirements that may need it
        """
        sub_config_path = interfaces.configuration.path_join(config_path, requirement.name)
        if isinstance(requirement, interfaces.configuration.SymbolRequirement):
            # TODO: Potentially think about multiple symbol requirements in both the same and different levels of the requirement tree
            # TODO: Consider whether a single found kernel can fulfill multiple requirements
            suffix = ".json"
            if self.potential_kernels:
                # TODO: Check that the symbols for this kernel will fulfill the requirement
                kernel = None
                for pk in self.potential_kernels:
                    kernel = self.potential_kernels[pk]
                    if kernel:
                        kernel = kernel[0]
                        break
                if kernel:
                    # Check user symbol directory first, then fallback to the framework's library to allow for overloading
                    midfix = os.path.join(kernel['pdb_name'], kernel['GUID'] + "-" + str(kernel['age']))
                    idd_path = None
                    for prefix in self.prefixes:
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
                    else:
                        vollog.debug("Symbol library path not found: {}".format(midfix + suffix))
                else:
                    vollog.debug("No suitable kernel pdb signature found")
        else:
            for subreq in requirement.requirements.values():
                self.recurse_symbol_fulfiller(context, sub_config_path, subreq)

    def recurse_set_kernel_virtual_offset(self, context, config_path, requirement):
        """Traverses the requirement tree, looking for kernel_virtual_offset values that may need setting"""
        sub_config_path = interfaces.configuration.path_join(config_path, requirement.name)
        if isinstance(requirement, configuration.requirements.TranslationLayerRequirement):
            # TODO: Check that this is the right potential kernel to be using
            virtual_layer_name = context.config.get(sub_config_path, None)
            if virtual_layer_name and isinstance(context.memory[virtual_layer_name], layers.intel.Intel):
                physical_layer_name = context.config.get(
                    interfaces.configuration.path_join(sub_config_path, "memory_layer"), None)
                if physical_layer_name:
                    kernel = self.potential_kernels.get(virtual_layer_name, [None, ])[0]
                    if kernel:
                        # It seems the kernel is loaded at a fixed mapping (presumably because the memory manager hasn't started yet)
                        if context.memory[virtual_layer_name].bits_per_register == 64:
                            # The kernel starts in a chunk towards the end of the space
                            kvo = kernel['mz_offset'] + (
                                31 << int(
                                    math.ceil(math.log2(context.memory[virtual_layer_name].maximum_address + 1)) - 5))
                        else:
                            # The kernel starts exactly halfway through the address space, so shift the maximum_address down by 1
                            kvo = kernel['mz_offset'] + (
                                1 << (context.memory[virtual_layer_name].bits_per_register - 1))
                        try:
                            kvp = context.memory[virtual_layer_name].mapping(kvo, 0)
                            if (any([(p == kernel['mz_offset'] and l == physical_layer_name) for (_, p, _, l) in kvp])):
                                # Sit the virtual offset under the TranslationLayer it applies to
                                kvo_path = interfaces.configuration.path_join(sub_config_path, 'kernel_virtual_offset')
                                context.config[kvo_path] = kvo
                                vollog.debug(
                                    "Setting kernel_virtual_offset to {}".format(hex(kvo)))
                            else:
                                vollog.debug(
                                    "Potential kernel_virtual_offset did not map to expected location: {}".format(
                                        hex(kvo)))
                        except exceptions.PagedInvalidAddressException:
                            vollog.debug("Potential kernel_virtual_offset caused a page fault: {}".format(hex(kvo)))
        else:
            for subreq in requirement.requirements.values():
                self.recurse_set_kernel_virtual_offset(context, sub_config_path, subreq)

    def __call__(self, context, config_path, requirement):
        self.potential_kernels = self.recurse_pdb_finder(context, config_path, requirement)
        if self.potential_kernels:
            self.recurse_symbol_fulfiller(context, config_path, requirement)
            self.recurse_set_kernel_virtual_offset(context, config_path, requirement)
