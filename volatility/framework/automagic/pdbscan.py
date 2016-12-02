# pdbscan.py -- Scan Volatility Layers for Windows kernel PDB signatures
#

import logging
import os
import struct

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
                        yield (GUID, a, pdb_name, data_offset + name_offset + sig)
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

    def __init__(self):
        super().__init__()
        self.potential_kernels = []

    def recurse_pdb_finder(self, context, config_path, requirement):
        sub_config_path = interfaces.configuration.path_join(config_path, requirement.name)
        results = []
        if isinstance(requirement, interfaces.configuration.TranslationLayerRequirement):
            # Check for symbols in this layer
            # FIXME: optionally allow a full (slow) scan
            # FIXME: Determine the physical layer no matter the virtual layer
            layer_name = context.config.get(
                interfaces.configuration.path_join(config_path, requirement.name, "memory_layer"), None)
            if layer_name:
                results = scan(context, layer_name)
        else:
            for subreq in requirement.requirements.values():
                results += self.recurse_pdb_finder(context, sub_config_path, subreq)
        return results

    def recurse_symbol_fulfiller(self, context, config_path, requirement):
        sub_config_path = interfaces.configuration.path_join(config_path, requirement.name)
        if isinstance(requirement, interfaces.configuration.SymbolRequirement):
            # TODO: Check that the symbols for this kernel will fulfill the requirement
            # TODO: Potentially think about multiple symbol requirements in both the same and different levels of the requirement tree
            # TODO: Consider whether a single found kernel can fulfill multiple requirements
            if self.potential_kernels:
                kernel = self.potential_kernels[0]
                # Check user symbol directory first, then fallback to the framework's library to allow for overloading
                prefixes = [os.path.join(os.path.dirname(__file__), "..", "..", "symbols", "windows"),
                            os.path.join(os.path.dirname(__file__), "..", "symbols", "windows")]
                midfix = kernel['pdb_name'] + "-" + kernel['GUID'] + "-" + str(kernel['age'])
                suffixes = ['.json', '.json.xz']
                idd_path = None
                for prefix in prefixes:
                    for suffix in suffixes:
                        if os.path.exists(os.path.join(prefix, midfix + suffix)):
                            idd_path = "file://" + os.path.abspath(os.path.join(prefix, midfix + suffix))
                if idd_path:
                    clazz = "volatility.framework.symbols.windows.WindowsKernelIntermedSymbols"
                    # Set the discovered options
                    context.config[interfaces.configuration.path_join(sub_config_path, "class")] = clazz
                    context.config[interfaces.configuration.path_join(sub_config_path, "idd_filepath")] = idd_path
                    # Construct the appropriate symbol table
                    requirement.construct(context, config_path)
                else:
                    vollog.debug("Symbol library path not found: {}".format(midfix + suffix))
        else:
            for subreq in requirement.requirements.values():
                self.recurse_symbol_fulfiller(context, sub_config_path, subreq)

    def __call__(self, context, config_path, requirement):
        self.potential_kernels = list(self.recurse_pdb_finder(context, config_path, requirement))
        self.recurse_symbol_fulfiller(context, config_path, requirement)
