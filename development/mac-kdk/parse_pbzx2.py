# v2 pbzx stream handler
# My personal writeup on the differences here: https://gist.github.com/pudquick/29fcfe09c326a9b96cf5
#
# Pure python reimplementation of .cpio.xz content extraction from pbzx file payload originally here:
# http://www.tonymacx86.com/general-help/135458-pbzx-stream-parser.html
#
# Cleaned up C version (as the basis for my code) here, thanks to Pepijn Bruienne / @bruienne
# https://gist.github.com/bruienne/029494bbcfb358098b41

import os
import struct
import sys


def seekread(f, offset=None, length=0, relative=True):
    if offset is not None:
        # offset provided, let's seek
        f.seek(offset, [0, 1, 2][relative])
    if length:
        return f.read(length)
    return None


def parse_pbzx(pbzx_path):
    section = 0
    xar_out_path = f"{pbzx_path}.part{section:02d}.cpio.xz"
    with open(pbzx_path, "rb") as f:
        # pbzx = f.read()
        # f.close()
        magic = seekread(f, length=4)
        if magic != "pbzx":
            raise RuntimeError("Error: Not a pbzx file")
        # Read 8 bytes for initial flags
        flags = seekread(f, length=8)
        # Interpret the flags as a 64-bit big-endian unsigned int
        flags = struct.unpack(">Q", flags)[0]
        while flags & (1 << 24):
            with open(xar_out_path, "wb") as xar_f:
                xar_f.seek(0, os.SEEK_END)
                # Read in more flags
                flags = seekread(f, length=8)
                flags = struct.unpack(">Q", flags)[0]
                # Read in length
                f_length = seekread(f, length=8)
                f_length = struct.unpack(">Q", f_length)[0]
                xzmagic = seekread(f, length=6)
                if xzmagic != "\xfd7zXZ\x00":
                    # This isn't xz content, this is actually _raw decompressed cpio_ chunk of 16MB in size...
                    # Let's back up ...
                    seekread(f, offset=-6, length=0)
                    # ... and split it out ...
                    f_content = seekread(f, length=f_length)
                    section += 1
                    decomp_out = f"{pbzx_path}.part{section:02d}.cpio"
                    with open(decomp_out, "wb") as g:
                        g.write(f_content)
                    # Now to start the next section, which should hopefully be .xz (we'll just assume it is ...)
                    section += 1
                    xar_out_path = f"{pbzx_path}.part{section:02d}.cpio.xz"
                else:
                    f_length -= 6
                    # This part needs buffering
                    f_content = seekread(f, length=f_length)
                    tail = seekread(f, offset=-2, length=2)
                    xar_f.write(xzmagic)
                    xar_f.write(f_content)
                    if tail != "YZ":
                        raise RuntimeError("Error: Footer is not xar file footer")


def main():
    parse_pbzx(sys.argv[1])
    print(
        "Now xz decompress the .xz chunks, then 'cat' them all together in order into a single new.cpio file"
    )


if __name__ == "__main__":
    main()
