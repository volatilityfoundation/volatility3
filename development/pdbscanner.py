import struct
import sys

# TODO: Rather nasty hack, when volatility's actually installed this would be unnecessary
sys.path += ".."

from volatility.framework import interfaces, layers
from volatility.framework.automagic.pdbscan import scan

if __name__ == '__main__':
    import argparse

    from volatility.framework import contexts

    parser = argparse.ArgumentParser()
    parser.add_argument(
        "filenames", metavar = "FILE", nargs = "+", action = "store", help = "FILE to read for testing")

    args = parser.parse_args()

    ctx = contexts.Context()
    scan_layers = []
    for filename in args.filenames:

        index = args.filenames.index(filename)
        config_name = 'config' + str(index)
        base_name = 'data' + str(index)
        ctx.config[interfaces.configuration.path_join(config_name, "filename")] = filename
        base = layers.physical.FileLayer(ctx, config_name, base_name)

        ctx.memory.add_layer(base)

        # XXX What's the right way to check for LiME?
        (magic, ) = struct.unpack('<I', ctx.memory.read(base_name, 0, 4))
        if magic == layers.lime.LimeLayer.MAGIC:
            lime_name = 'data-lime' + str(index)
            lime_config_name = 'config-lime' + str(index)
            ctx.config[interfaces.configuration.path_join(lime_config_name, "base_layer")] = base_name
            lime = layers.lime.LimeLayer(ctx, lime_config_name, lime_name)

            ctx.memory.add_layer(lime)
            base_name = lime_name
        scan_layers.append((filename, base_name))

    for (filename, layername) in scan_layers:
        print("[*] Scanning " + filename + "...")
        hits = scan(ctx, layername, page_size = layers.intel.Intel.page_size)
        if hits:
            for hit in hits:
                GUID = hit["GUID"]
                age = hit["age"]
                pdb_name = hit["pdb_name"]
                signature_offset = hit["signature_offset"]
                mz_offset = hit["mz_offset"]
                print("[!] PDB Guess: %s/%s%d MZ=0x%x" % (pdb_name, GUID, age, mz_offset))
        else:
            print("[X] No kernel PDBs found")
        print()
