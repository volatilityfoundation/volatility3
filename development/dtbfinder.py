import statistics
import sys

# TODO: Rather nasty hack, when volatility's actually installed this would be unnecessary
sys.path += ".."

from volatility.framework import contexts
from volatility.framework import interfaces
from volatility.framework import layers
from volatility.framework.automagic import windows

if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("filenames", metavar = "FILE", nargs = "+", action = "store", help = "FILE to read for testing")
    parser.add_argument("--32bit", action = "store_false", dest = "bit32", help = "Disable 32-bit scanning")
    parser.add_argument("--64bit", action = "store_false", dest = "bit64", help = "Disable 64-bit scanning")
    parser.add_argument("--pae", action = "store_false", dest = "pae", help = "Disable pae scanning")
    parser.add_argument("-l", "--lime", action = "store_true", dest = "lime", help = "All files are LIME format")
    parser.add_argument("-s", "--selfref", action = "store_true", dest = "selfref",
                        help = "Run more generic self-referential tests scanner")
    parser.add_argument("-v", "--verbose", action = "count", default = 0,
                        help = "Increase the verbosity of the information returned")

    args = parser.parse_args()

    ctx = contexts.Context()
    for filename in args.filenames:
        ctx.config[
            interfaces.configuration.path_join('config' + str(args.filenames.index(filename)), "filename")] = filename
        data = layers.physical.FileLayer(ctx,
                                         'config' + str(args.filenames.index(filename)),
                                         'data' + str(args.filenames.index(filename)))
        ctx.memory.add_layer(data)
        if args.lime:
            ctx.config[interfaces.configuration.path_join('lime-config' + str(args.filenames.index(filename)),
                                                          "base_layer")] = 'data' + str(args.filenames.index(filename))
            data = layers.lime.LimeLayer(ctx,
                                         'lime-config' + str(args.filenames.index(filename)),
                                         'lime-data' + str(args.filenames.index(filename)))
            ctx.memory.add_layer(data)

    layername = 'data'
    if args.lime:
        layername = 'lime-data'

    tests = []
    if args.selfref:
        if args.bit32:
            tests.append(windows.DtbSelfRef32bit())
        if args.bit64:
            tests.append(windows.DtbSelfRef64bit())
    else:
        if args.bit32:
            tests.append(windows.DtbTest32bit())
        if args.bit64:
            tests.append(windows.DtbTest64bit())
        if args.pae:
            tests.append(windows.DtbTestPae())

    if tests:
        for i in range(len(args.filenames)):
            print("[*] Scanning " + args.filenames[i] + "...")
            scan_results = ctx.memory[layername + str(i)].scan(ctx, windows.PageMapScanner(tests))

            # Self-referential tests need post-processing to gather the most likely offset
            if args.selfref:
                selfref_results = dict([(test, dict()) for test in tests])
                for test, result in scan_results:
                    dtb, refs = result
                    test_dict = selfref_results[test]
                    for ref in refs:
                        # Initialize the value if necessary
                        tmp = test_dict.get(ref, set())
                        tmp.add(dtb)
                        test_dict[ref] = tmp
                    selfref_results[test] = test_dict
                scan_results = []
                print("   Self-referential data")
                # Sort by largest pointer size, since the self-ref finder will find larger sizes when searching for smaller)
                for test in sorted(selfref_results, key = lambda x: -x.ptr_size):
                    best_found = None
                    print("     " + test.layer_type.__name__ + ": ")

                    test_dict = selfref_results[test]
                    for ref in sorted(test_dict, key = lambda x: -len(test_dict[x])):
                        # Most self-referential DTBs should turn up multiple times because multiple processes should have their own DTB
                        if len(test_dict[ref]) < 2:
                            continue
                        if best_found is None:
                            # Most processes are spread out across significantly different pages
                            # Therefore the standard deviation should be significant
                            if statistics.stdev(test_dict[ref]) > 0x100000:
                                for dtb in test_dict[ref]:
                                    scan_results.append((test, dtb))
                                best_found = ref
                        if args.verbose > 1 or best_found == ref:
                            print("       " + hex(ref) + ": " + ", ".join([hex(x) for x in sorted(test_dict[ref])]))
            print("   Results")

            # Populate the guesses based on the scan_results
            guesses = dict([(test.layer_type.__name__, set()) for test in tests])
            for test, dtb in scan_results:
                guesses[test.layer_type.__name__].add(dtb)

            # Guesses should be a dictionary mapping tests to sets of most likely dtbs, the lowest of which is then chosen
            arch = None
            for guess_arch in sorted(guesses, key = lambda x: -len(guesses[x])):
                if not arch and len(guesses[guess_arch]) > 0:
                    arch = guess_arch
                if args.verbose:
                    print("    " + guess_arch + ": " + ", ".join([hex(x) for x in sorted(guesses[guess_arch])]))
            if arch:
                print("[!] OS Guess:", arch, "with DTB", hex(list(guesses[arch])[0]))
            else:
                print("[X] No DTBs found")
            print()
    else:
        print("[X] No tests selected")
