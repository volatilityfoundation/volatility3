# This file is Copyright 2026 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

import logging
import struct
from dataclasses import dataclass
from typing import BinaryIO, Callable, Union

from volatility3.framework.renderers import NotApplicableValue

vollog = logging.getLogger(__name__)


NT_FILE = 0x46494C45  # 'FILE' in big endian

# Alignment values
NOTE_ALIGN = 4
PAGE_SIZE = 0x1000

# Program header flags
PF_X = 1
PF_W = 2
PF_R = 4

# Program header types
PT_LOAD = 1
PT_NOTE = 4


def align(x, a):
    return (x + (a - 1)) & ~(a - 1)


@dataclass
class Segment:
    vaddr: int
    """Virtual address of the segment."""
    size: int
    """Size of the segment. On-disk and in-mem size is identical for dumps."""
    flags: int
    """Segment permissions (combination of PF_* values)."""
    name: str
    """Name of the segment (i.e. image path), can be empty."""
    offset: int = 0
    """Internal field for serialization purposes."""


class CoreDumpWriter:
    """Creates an ELF core dump file for a process."""

    def __init__(self, bits: int) -> None:
        self.segments: list[Segment] = []
        self.bits = bits

        if self.bits == 32:
            self.machine = 3  # EM_X86_86
            self.program_header_size = 32
        else:
            self.machine = 0x3E  # EM_X86_64
            self.program_header_size = 56

    def add_segment(
        self, vaddr: int, size: int, flags: int, name: Union[str, NotApplicableValue]
    ) -> None:
        """Adds information about a virtual memory segment to the dump."""
        if isinstance(name, NotApplicableValue):
            name = ""
        self.segments.append(Segment(vaddr, size, flags, name))

    def build_note(self, name: str, n_type: int, desc: bytes) -> bytes:
        """
        Builds a Note Section with the given specifications.

        Spec: https://refspecs.linuxfoundation.org/elf/gabi4+/ch5.pheader.html#note_section
        """
        namesz = len(name) + 1
        descsz = len(desc)

        out = struct.pack("<III", namesz, descsz, n_type)
        out += name.encode() + b"\x00"
        out += b"\x00" * (align(namesz, NOTE_ALIGN) - namesz)

        out += desc
        out += b"\x00" * (align(descsz, NOTE_ALIGN) - descsz)

        return out

    def build_file_note(self) -> bytes:
        """Builds a CORE note of type NT_FILE, containing all of our segment names."""
        file_entries = []
        filenames = b""

        for seg in self.segments:
            if seg.name:
                start = seg.vaddr
                end = start + seg.size

                file_entries.append((start, end))
                filenames += seg.name.encode("utf-8") + b"\x00"

        fmt = "I" if self.bits == 32 else "Q"
        note_desc = struct.pack(f"<{fmt}{fmt}", len(file_entries), PAGE_SIZE)

        for s, e in file_entries:
            note_desc += struct.pack(f"<{fmt}{fmt}{fmt}", s, e, 0)  # third word is file_ofs

        note_desc += filenames

        return self.build_note("CORE", NT_FILE, note_desc)

    def _make_elf_header(self, phnum: int) -> bytes:
        """
        Creates an ELF header of type ET_CORE.

        Spec: https://refspecs.linuxfoundation.org/elf/gabi4+/ch4.eheader.html
        """
        if phnum >= 0xFFFF:
            # A file with this many segments is not impossible, but it would require
            # extra hoops (putting the count into the first section).
            raise ValueError(f"Unsupported number of segments for dump file: {phnum}")

        if self.bits == 32:
            fmt = "<I"
            e_ident = (
                b"\x7f\x45\x4c\x46\x01\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            )
            e_ehsize_int = 52
        else:
            fmt = "<Q"
            e_ident = (
                b"\x7f\x45\x4c\x46\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            )
            e_ehsize_int = 64

        # put program headers directly after the ELF header
        phoff = e_ehsize_int

        e_type = struct.pack("<H", 4)  # ET_CORE
        e_machine = struct.pack("<H", self.machine)
        e_version = struct.pack("<I", 1)
        e_entry = struct.pack(fmt, 0)
        e_phoff = struct.pack(fmt, phoff)
        e_shoff = struct.pack(fmt, 0)
        e_flags = struct.pack("<I", 0)
        e_ehsize = struct.pack("<H", e_ehsize_int)
        e_phentsize = struct.pack("<H", self.program_header_size)
        e_phnum = struct.pack("<H", phnum)
        e_shentsize = struct.pack("<H", 0)
        e_shnum = struct.pack("<H", 0)
        e_shstrndx = struct.pack("<H", 0)

        header = (
            e_ident
            + e_type
            + e_machine
            + e_version
            + e_entry
            + e_phoff
            + e_shoff
            + e_flags
            + e_ehsize
            + e_phentsize
            + e_phnum
            + e_shentsize
            + e_shnum
            + e_shstrndx
        )

        # should never fail as we make the header ourselves
        assert len(header) == e_ehsize_int, \
               f"Making Elf header for arch {self.bits} created a header of {len(header)} bytes. Cannot proceed"

        return header

    def _make_phdr(
        self, type: int, flags: int, offset: int, vaddr: int, size: int, align: int
    ) -> bytes:
        """
        Serializes a program header.

        Spec: https://refspecs.linuxfoundation.org/elf/gabi4+/ch5.pheader.html
        """
        if self.bits == 32:
            return struct.pack(
                "<IIIIIIII",
                type,
                offset,
                vaddr,
                0,  # paddr
                size,
                size,
                flags,
                align
            )
        else:
            return struct.pack(
                "<IIQQQQQQ",
                type,
                flags,
                offset,
                vaddr,
                0,  # paddr
                size,
                size,
                align
            )

    def dump(
        self, fp: BinaryIO, data_callback: Callable[[BinaryIO, int, int], None]
    ) -> None:
        """
        Writes the core dump into the given BinaryIO. data_callback will be called with the
        file handle, start address and size whenever actual segment data needs to be written.
        """
        note_blobs = [self.build_file_note()]

        phnum = len(note_blobs) + len(self.segments)

        elf_header = self._make_elf_header(phnum)
        data_start = align(len(elf_header) + phnum * self.program_header_size,
                           PAGE_SIZE)

        offset = data_start
        phdr_blob = b""

        for note_blob in note_blobs:
            phdr_blob += self._make_phdr(PT_NOTE, 0, offset,
                                         0, len(note_blob), NOTE_ALIGN)
            offset += align(len(note_blob), NOTE_ALIGN)

        for seg in self.segments:
            offset = align(offset, PAGE_SIZE)

            phdr_blob += self._make_phdr(PT_LOAD, seg.flags, offset,
                                         seg.vaddr, seg.size, PAGE_SIZE)

            seg.offset = offset
            offset += seg.size

        if fp.tell() != 0:
            raise ValueError("File passed to CoreDumpWriter.dump() must be empty")

        fp.write(elf_header)
        fp.write(phdr_blob)

        # pad to data_start
        cur = fp.tell()
        fp.write(b"\x00" * (data_start - cur))

        # write notes
        for note_blob in note_blobs:
            fp.write(note_blob)
            fp.write(b"\x00" * (align(len(note_blob), NOTE_ALIGN) - len(note_blob)))

        # write segments
        for seg in self.segments:
            cur = fp.tell()
            if cur < seg.offset:
                fp.write(b"\x00" * (seg.offset - cur))

            data_callback(fp, seg.vaddr, seg.size)
