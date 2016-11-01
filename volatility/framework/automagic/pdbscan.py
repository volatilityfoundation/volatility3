# pdbscan.py -- Scan Volatility Layers for Windows kernel PDB signatures
#
if __name__ == "__main__":
    import os
    import sys

    sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(__file__)))))

import struct

from volatility.framework import layers, interfaces

PAGE_SIZE = 0x1000

_kernel_pdbs = [
    b"ntkrnlmp.pdb",
    b"ntkrnlpa.pdb",
    b"ntkrpamp.pdb",
    b"ntoskrnl.pdb",
]

_RSDS_format = struct.Struct("<16BI")


class PdbSigantureScanner(interfaces.layers.ScannerInterface):
    overlap = 0x4000

    def __call__(self, data, data_offset):
        sig = data.find(b"RSDS")
        pdb_hits = []
        while sig >= 0:
            null = data.find(b'\0', sig + 4 + _RSDS_format.size)
            if null > -1:
                if (null - sig - _RSDS_format.size) <= 100:
                    name_offset = sig + 4 + _RSDS_format.size
                    pdb_name = data[name_offset:null]
                    if pdb_name in _kernel_pdbs:

                        ## thie ordering is intentional due to mixed endianness in the GUID
                        (g3, g2, g1, g0, g5, g4, g7, g6, g8, g9, ga, gb, gc, gd, ge, gf, a) = \
                            _RSDS_format.unpack(data[sig + 4:name_offset])

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
    for (GUID, age, pdb_name, signature_offset) in ctx.memory[layername].scan(ctx, PdbSigantureScanner()):
        mz_offset = None
        sig_pfn = signature_offset // PAGE_SIZE

        for i in range(sig_pfn, min_pfn, -1):
            if not ctx.memory[layer_name].is_valid(i * PAGE_SIZE, 2):
                break

            data = ctx.memory.read(layer_name, i * PAGE_SIZE, 2)
            if data == b'MZ':
                mz_offset = i * PAGE_SIZE
                break
        min_pfn = sig_pfn

        results.append((GUID, age, pdb_name, signature_offset, mz_offset))

    return results


if __name__ == '__main__':
    import argparse

    from volatility.framework.symbols import native
    from volatility.framework import contexts

    parser = argparse.ArgumentParser()
    parser.add_argument("filenames", metavar = "FILE", nargs = "+",
                        action = "store", help = "FILE to read for testing")

    args = parser.parse_args()

    nativelst = native.x86NativeTable
    ctx = contexts.Context(nativelst)
    scan_layers = []
    for filename in args.filenames:

        index = args.filenames.index(filename)
        config_name = 'config' + str(index)
        base_name = 'data' + str(index)
        ctx.config[interfaces.configuration.path_join(config_name, "filename")] = filename
        base = layers.physical.FileLayer(ctx,
                                         config_name,
                                         base_name)

        ctx.memory.add_layer(base)

        # XXX What's the right way to check for LiME?
        (magic,) = struct.unpack('<I', ctx.memory.read(base_name, 0, 4))
        if magic == layers.lime.LimeLayer.MAGIC:
            lime_name = 'data-lime' + str(index)
            lime_config_name = 'config-lime' + str(index)
            ctx.config[interfaces.configuration.path_join(lime_config_name, "base_layer")] = base_name
            lime = layers.lime.LimeLayer(ctx,
                                         lime_config_name,
                                         lime_name)

            ctx.memory.add_layer(lime)
            base_name = lime_name
        scan_layers.append((filename, base_name))

    for (filename, layername) in scan_layers:
        print("[*] Scanning " + filename + "...")
        hits = scan(ctx, layername)
        if hits:
            for (GUID, age, pdb_name, signature_offset, mz_offset) in hits:
                print("[!] PDB Guess: %s/%s%d MZ=0x%x" %
                      (pdb_name.decode("utf-8"), GUID, age, mz_offset))
        else:
            print("[X] No kernel PDBs found")
        print()
