# This file is Copyright 2025 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
import logging
import struct

from typing import (
    List,
    Optional,
    Tuple,
    Dict,
)

from volatility3 import framework
from volatility3.framework import (
    interfaces,
    exceptions,
    symbols,
)
from volatility3.framework.constants import linux as linux_constants
from volatility3.framework.symbols.linux import extensions

vollog = logging.getLogger(__name__)

# This module is responsbile for producing an ELF file of a kernel module (LKM) loaded in memory
# This extraction task is quite complicated as the Linux kernel discards the ELF header at load time
# Due to this, to support static analysis, we must create an ELF header and proper file based on the sections
# There are also several other significant complications that we must deal with when trying to extract an LKM
# that can be analyzed with static analysis tools
# First, the .strtab points somewhere random and is kept off the module structure, not with the other sections
# Second, all of the symbols (.symtab) have mangled members that we must patch for anything to make sense
# Third, the section name string table (.shstrtab) is not an allocated section, meaning its not in memory
# Not having the .shstrtab makes analysis impossible-to-difficult for static analysis tools. To work around this,
# we create the .shstrtab based on the sections in memory and then glue it in as the final section

# ModuleExtract.extract_module is the entry point and only visible method for plugins


class ModuleExtract(interfaces.configuration.VersionableInterface):
    """Extracts Linux kernel module structures into an analyzable ELF file"""

    _version = (1, 0, 0)
    _required_framework_version = (2, 25, 0)

    framework.require_interface_version(*_required_framework_version)

    @classmethod
    def _get_module_section_count(
        cls,
        context: interfaces.context.ContextInterface,
        vmlinux_name: str,
        module: extensions.module,
        grp: interfaces.objects.ObjectInterface,
    ) -> int:
        """
        Used to manually determine the section count for kernels that do not track
        this count directly within the attribute structures
        """
        kernel = context.modules[vmlinux_name]

        count = 0

        try:
            array = kernel.object(
                object_type="array",
                offset=grp.attrs,
                sub_type=kernel.get_type("pointer"),
                count=50,
                absolute=True,
            )

            # Walk up to 50 sections counting until we reach the end or a page fault
            for sect in array:
                if sect.vol.offset == 0:
                    break

                count += 1

        except exceptions.InvalidAddressException:
            # Use whatever count we reached before the error
            vollog.debug(
                f"Exception hit counting sections for module at {module.vol.offset:#x}"
            )

        return count

    @classmethod
    def _find_section(
        cls, section_lookups: List[Tuple[str, int, int, int]], sym_address: int
    ) -> Optional[Tuple[str, int, int, int]]:
        """
        Finds the section containing `sym_address`
        """
        for name, index, address, size in section_lookups:
            if address <= sym_address < address + size:
                return name, index, address, size

        return None

    @classmethod
    def _get_st_info_for_sym(
        cls, sym: interfaces.objects.ObjectInterface, sym_address: int, sect_name: str
    ) -> bytes:
        """
        This is a helper function called from `_fix_sym_table`

        Calculates the `st_info` value for the given symbol

        Spec: https://refspecs.linuxbase.org/elf/gabi4+/ch4.symtab.html
        """
        if sym.st_name > 0:
            # Global symbol
            bind = linux_constants.STB_GLOBAL

            if sym_address == 0:
                sect_type = linux_constants.STT_NOTYPE
            elif sect_name:
                # rela = relocations
                if sect_name.find(".text") != -1 and sect_name.find(".rela") == -1:
                    sect_type = linux_constants.STT_FUNC
                else:
                    sect_type = linux_constants.STT_OBJECT

            else:
                # outside the module being extracted
                sect_type = linux_constants.STT_NOTYPE

        else:
            # Local symbol
            bind = linux_constants.STB_LOCAL
            sect_type = linux_constants.STT_SECTION

        # Build the st_info as ELF32_ST_INFO/ELF64_ST_INFO
        bind_bits = (bind << 4) & 0xF0
        type_bits = sect_type & 0xF

        st_info_int = (bind_bits | type_bits) & 0xFF

        return struct.pack("B", st_info_int)

    @classmethod
    def _get_fixed_sym_fields(
        cls,
        st_fmt: str,
        sym: interfaces.objects.ObjectInterface,
        sections: List[Tuple[str, int, int, int]],
    ) -> Tuple[str, int, int, int]:
        """
        This is a helper function called from `_fix_sym_table`

        The st_value, st_info, and st_shndx fields of each symbol are changed/mangled while loading
        Static analysis tools do not understand these transformed values as they only make sense to the kernel loader
        We must de-mangle these to have analysis tools understand symbols (a key aspect)
        """
        # Start by trying to map a symbol to its section
        sym_address = sym.st_value
        sect_info = cls._find_section(sections, sym_address)

        if not sect_info:
            # Symbol does not point into the module being extracted
            sect_name, sect_index, sect_address = None, None, None
            st_value_int = sym_address
        else:
            # relative address inside the section
            sect_name, sect_index, sect_address, _ = sect_info
            st_value_int = sym_address - sect_address

        # Get the fixed st_value, st_info, and st_shndx that are broken in the mapped file

        # formatted to be written into the extracted file
        st_value = struct.pack(st_fmt, st_value_int)

        # returns formatted to be written into the extracted file
        st_info = cls._get_st_info_for_sym(sym, sym_address, sect_name)

        # format to reference its section, if any
        if sect_name:
            st_shndx = struct.pack("<H", sect_index)
        else:
            st_shndx = struct.pack("<H", sym.st_shndx)

        return sect_name, st_value, st_info, st_shndx

    @classmethod
    def _fix_sym_table(
        cls,
        context: interfaces.context.ContextInterface,
        vmlinux_name: str,
        original_sections: Dict[int, str],
        section_sizes: Dict[int, int],
        sym_type_name: str,
        st_fmt: str,
        module: extensions.module,
    ) -> Optional[bytes]:
        """
        This function implements the most painful part of the reconstruction

        The symbols in .symtab are broken/mangled during loading.
        We need to normalize these for static analysis tools to understand the references.
        Without proper symbols, analysis is pretty pointless and gets nowhere.

        Spec: https://refspecs.linuxbase.org/elf/gabi4+/ch4.symtab.html
        """
        kernel = context.modules[vmlinux_name]

        # Gather the section information into a list
        section_lookups: List[Tuple[str, int, int, int]] = []
        for index, (address, name) in enumerate(original_sections.items()):
            # We are fixing symtab references...
            if name == ".symtab":
                continue

            size = section_sizes[address]

            # Add 1 to account for leading NULL section
            section_lookups.append((name, index + 1, address, size))

        # Build the array of symbols as they are in memory
        sym_type = kernel.get_type(sym_type_name)

        symbols = kernel.object(
            object_type="array",
            subtype=sym_type,
            offset=module.section_symtab,
            count=module.num_symtab,
            absolute=True,
        )

        # used to hold the new (fixed) symbol table
        sym_table_data = b""

        # build a correct/normalized Elf32_Sym or Elf64_Sym for each symbol
        for sym in symbols:
            # get the mangled fields' correct values
            sect_name, st_value, st_info, st_shndx = cls._get_fixed_sym_fields(
                st_fmt, sym, section_lookups
            )

            # these aren't mangled during loading
            st_name = struct.pack("<I", sym.st_name)
            st_other = struct.pack("B", sym.st_other)
            st_size = struct.pack(st_fmt, sym.st_size)

            # The order as in the ELF specification. The order is not the same between 32 and 64 bit symbols
            if st_fmt == "<I":
                sym_data = st_name + st_value + st_size + st_info + st_other + st_shndx
            else:
                sym_data = st_name + st_info + st_other + st_shndx + st_value + st_size

            # This should never happen regardless of smear or other issues in the data. We build the structure to spec.
            if len(sym_data) != sym_type.size:
                vollog.error(
                    f"Size of sym_data is {len(sym_data)} expected {sym_type.size} for symbol at value {sym.st_value} in section {sect_name}"
                )
                return None

            # add the symbol's data to the overall symbol table
            sym_table_data += sym_data

        if len(sym_table_data) == 0:
            sym_table_data = None

        return sym_table_data

    @classmethod
    def _enumerate_original_sections(
        cls,
        context: interfaces.context.ContextInterface,
        vmlinux_name: str,
        module: extensions.module,
    ) -> Optional[Dict[int, str]]:
        """
        Enumerates the module's sections as maintained by the kernel after load time
        'Early' sections like .init.text and .init.data are discarded after module
        initialization, so they are not expected to be in memory during extraction
        """
        if hasattr(module.sect_attrs, "nsections"):
            num_sections = module.sect_attrs.nsections
        else:
            num_sections = cls._get_module_section_count(
                context, vmlinux_name, module.sect_attrs.grp
            )

        if num_sections > 1024 or num_sections == 0:
            vollog.debug(
                f"Invalid number of sections ({num_sections}) for module at offset {module.vol.offset:#x}"
            )
            return None

        vmlinux = context.modules[vmlinux_name]

        # This is declared as a zero sized array, so we create ourselves
        attribute_type = module.sect_attrs.attrs.vol.subtype

        sect_array = vmlinux.object(
            object_type="array",
            subtype=attribute_type,
            offset=module.sect_attrs.attrs.vol.offset,
            count=num_sections,
            absolute=True,
        )

        sections: Dict[int, str] = {}

        # for each section, gather its name and address
        for index, section in enumerate(sect_array):
            name = section.get_name()

            sections[section.address] = name

        return sections

    @classmethod
    def _parse_sections(
        cls,
        context: interfaces.context.ContextInterface,
        vmlinux_name: str,
        module: extensions.module,
    ) -> Optional[Tuple[List, int, int]]:
        """
        This function first parses the sections as maintained by the kernel
        It then orders the sections by load address, and then gathers the data of each section
        We also track the file_offset to correctly have alignment in the output file

        .symtab requires special handling as its so broken in memory as described in `_fix_sym_table`
        The data of .strtab is read directly off the module structure and not its section
        as the section from the original module has no meaning after loading as the kernel does not reference it.
        """
        original_sections = cls._enumerate_original_sections(
            context, vmlinux_name, module
        )
        if original_sections is None:
            return None

        kernel = context.modules[vmlinux_name]
        kernel_layer = context.layers[kernel.layer_name]

        if symbols.symbol_table_is_64bit(context, kernel.symbol_table_name):
            sym_type = "Elf64_Sym"
            elf_hdr_type = "Elf64_Ehdr"
            st_fmt = "<Q"
        else:
            sym_type = "Elf32_Sym"
            elf_hdr_type = "Elf32_Ehdr"
            st_fmt = "<I"

        # At this point, we have the sections starting addresses and names,
        # but the kernel does not track the size
        # To recover the size, we sort by address and then use the next section as the boundary to calculate size
        # .symtab (the symbol table) and .strtab (the strings table) require special handling.
        # All others can be read with padding

        # get the addresses in sorted order, can index into `original_sections` for names
        sorted_addresses = sorted(original_sections.keys())

        # We need to track where .symtab is for symbol name offsets
        symtab_address = None
        strtab_index = None

        # Section data starts after the file header
        file_offset = kernel.get_type(elf_hdr_type).vol.size

        # The ordered set of sections along with their fixed data
        updated_sections: List[Tuple[str, int, int, bytes]] = []

        # A mapping of section start addresses to sizes
        # original_sections does not have this information for reasons explained above
        section_sizes: Dict[int, int] = {}

        for index, address in enumerate(sorted_addresses):
            sect_name = original_sections[address]

            # Read out the string table. The full size is not kept, so we give each symbol's string up to 256 bytes
            if sect_name == ".strtab":
                # Read out symbol strings, giving up to 256 bytes per symbol
                data = kernel_layer.read(
                    module.section_strtab, module.num_symtab * 256, pad=True
                )

                # The string table should end with two NULLs, but the kernel does not enforce this
                end_index = data.find(b"\x00\x00")
                if end_index != -1:
                    data = data[: end_index + 1]

                strtab_index = index

            # The symbol table in memory is completely transformed and broken from how it appears on disk
            # We need to process it last to fix the symbol table entries back to their correct values
            elif sect_name == ".symtab":
                symtab_address = address
                continue
            else:
                # Compute based on the boundary of the next address-sorted section
                try:
                    # Get the next section in order
                    next_address = sorted_addresses[index + 1]
                    size = next_address - address
                except IndexError:
                    ## We are at the last section so we need to pick a size
                    size = 0x10000
                    vollog.debug(f"Defaulting section {sect_name} to size {size:#x}")

                # Read the section normally..
                data = kernel_layer.read(address, size, pad=True)

            # store the section information in order
            updated_sections.append((sect_name, address, file_offset, data))

            # Track sizes of each section
            section_sizes[address] = len(data)

            file_offset += len(data)

        if symtab_address:
            # Perform the painful demangling of symbol table structures
            data = cls._fix_sym_table(
                context,
                vmlinux_name,
                original_sections,
                section_sizes,
                sym_type,
                st_fmt,
                module,
            )
            if not data:
                vollog.debug(
                    f"Coult not construct a symbol table for module at {module.vol.offset}. Cannot recover."
                )
                return None, None, None

            symtab_index = len(updated_sections)

            # Manually add symtab with the correct data
            updated_sections.append((".symtab", symtab_address, file_offset, data))

        else:
            vollog.debug(
                f"Did not find a .symtab section for module at {module.vol.offset:#x}. Cannot recover."
            )
            return None, None, None

        return updated_sections, strtab_index, symtab_index

    @classmethod
    def _make_elf_header(
        cls, bits: int, sect_hdr_offset: int, num_sections: int
    ) -> Optional[bytes]:
        """
        Creates a `bits` bit ELF header for the file based on recovered values
        Called last as it needs information computed from the sections

        Spec: https://refspecs.linuxfoundation.org/elf/gabi4+/ch4.eheader.html
        """
        if bits == 32:
            fmt = "<I"
            e_ident = (
                b"\x7f\x45\x4c\x46\x01\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            )
            e_machine_int = 3  # EM_X86_86
            e_ehsize_int = 52
            e_shentsize_int = 40
            header_size = 52
        else:
            fmt = "<Q"
            e_ident = (
                b"\x7f\x45\x4c\x46\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            )
            e_machine_int = 0x3E  # EM_X86_64
            e_ehsize_int = 64
            e_shentsize_int = 64
            header_size = 64

        e_type = struct.pack("<H", 1)  # relocateble
        e_machine = struct.pack("<H", e_machine_int)
        e_version = struct.pack("<I", 1)
        e_entry = b"\x00" * int(
            bits / 8
        )  # The .init sections are freed after module load
        e_phoff = b"\x00" * int(bits / 8)  # No program headers
        e_shoff = struct.pack(fmt, sect_hdr_offset)
        e_flags = b"\x00\x00\x00\x00"
        e_ehsize = struct.pack("<H", e_ehsize_int)
        e_phentsize = b"\x00\x00"
        e_phnum = b"\x00\x00"
        e_shentsize = struct.pack("<H", e_shentsize_int)
        e_shnum = struct.pack("<H", num_sections + 1)
        e_shstrndx = struct.pack("<H", num_sections)

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

        # should never happen as we make the header ourselves
        if len(header) != header_size:
            vollog.error(
                f"Making Elf header for arch {bits} created a header of {len(header)} bytes. Cannot proceed"
            )
            return None

        return header

    @classmethod
    def _calc_sect_type(cls, section_name: str) -> Optional[int]:
        """
        This function makes a best effort to map common section names
        to their attributes
        """
        known_sections = {
            ".note.gnu.build-id": linux_constants.SHT_NOTE,
            ".text": linux_constants.SHT_PROGBITS,
            ".init.text": linux_constants.SHT_PROGBITS,
            ".exit.text": linux_constants.SHT_PROGBITS,
            ".static_call.text": linux_constants.SHT_PROGBITS,
            ".rodata": linux_constants.SHT_PROGBITS,
            ".modinfo": linux_constants.SHT_PROGBITS,
            "__param": linux_constants.SHT_PROGBITS,
            ".data": linux_constants.SHT_PROGBITS,
            ".gnu.linkonce.this_module": linux_constants.SHT_PROGBITS,
            ".comment": linux_constants.SHT_PROGBITS,
            ".shstrtab": linux_constants.SHT_STRTAB,
            ".symtab": linux_constants.SHT_SYMTAB,
            ".strtab": linux_constants.SHT_STRTAB,
        }

        sect_type_val = linux_constants.SHT_PROGBITS

        if section_name.find(".rela.") != -1:
            sect_type_val = linux_constants.SHT_RELA

        elif section_name in known_sections:
            sect_type_val = known_sections[section_name]

        return sect_type_val

    # all sections from memory are allocated (SHF_ALLOC)
    # special check certain other sections to try and ensure extra flags are added where needed
    @classmethod
    def _calc_sect_flags(cls, name: str) -> int:
        """
        Make a best effort to map common section names to their permissions
        If we miss a section here, users of common static analysis tools can mark the
        sections are writable or executable manually, but that becomes very cumbersome
        and breaks initial analysis by the tool
        """
        # All sections in memory are allocated (`A` in readelf -S)
        flags = linux_constants.SHF_ALLOC

        if name in [".text", ".init.text", ".exit.text", ".static_call.text"]:
            flags = flags | linux_constants.SHF_EXECINSTR

        elif name in [
            ".data",
            ".init.data",
            ".exit.data",
            ".bss",
            "__tracepoints",
            ".data.once",
            "_ftrace_events",
            ".gnu.linkonce.this_module",
        ]:
            flags = flags | linux_constants.SHF_WRITE

        return flags

    @classmethod
    def _calc_link(
        cls, name: str, strtab_index: int, symtab_index: int, sect_type: int
    ) -> int:
        """
        Calculates the link value for a section

        The most important ones are symtab indexes for relocations
        and to point the symbol table to the string tab

        Spec: https://refspecs.linuxbase.org/elf/gabi4+/ch4.sheader.html
        """
        # looking for RELA sections
        if name.find(".rela.") != -1:
            return symtab_index

        # per spec: "The section header index of the associated string table."
        elif sect_type == linux_constants.SHT_SYMTAB:
            return strtab_index

        return 0

    @classmethod
    def _calc_entsize(cls, name: str, sect_type: int, bits: int) -> int:
        """
        Calculates the entsize for relocation sections and the symbol table section

        Spec: https://refspecs.linuxbase.org/elf/gabi4+/ch4.sheader.html
        """
        # looking for RELA sections
        if name.find(".rela.") != -1:
            return 24

        # per spec: "The section header index of the associated string table."
        elif sect_type == linux_constants.SHT_SYMTAB:
            if bits == 32:
                return 16
            else:
                return 24

        return 0

    @classmethod
    def _make_section_header(
        cls,
        bits: int,
        name_index: int,
        name: str,
        address: int,
        size: int,
        file_offset: int,
        strtab_index: int,
        symtab_index: int,
    ) -> Optional[bytes]:
        """
        Creates a section header (Elf32_Shdr or Elf64_Shdr) for the given section
        """
        if bits == 32:
            fmt = "<I"
            sect_size = 40
        else:
            fmt = "<Q"
            sect_size = 64

        sect_header_type_int = cls._calc_sect_type(name)

        flags = cls._calc_sect_flags(name)

        link = cls._calc_link(name, strtab_index, symtab_index, sect_header_type_int)

        entsize = cls._calc_entsize(name, sect_header_type_int, bits)

        try:
            sh_name = struct.pack("<I", name_index)
            sh_type = struct.pack("<I", sect_header_type_int)
            sh_flags = struct.pack(fmt, flags)
            sh_addr = struct.pack(fmt, address)
            sh_offset = struct.pack(fmt, file_offset)
            sh_size = struct.pack(fmt, size)
            sh_link = struct.pack("<I", link)
            sh_info = b"\x00" * 4
            sh_addralign = struct.pack(fmt, 1)
            sh_entsize = struct.pack(fmt, entsize)

        # catch overflows of offset/address/size
        except struct.error:
            vollog.debug(
                f"Unable to build section header for section {name} at address {address:#x}"
            )
            return None

        data = (
            sh_name
            + sh_type
            + sh_flags
            + sh_addr
            + sh_offset
            + sh_size
            + sh_link
            + sh_info
            + sh_addralign
            + sh_entsize
        )

        # This should never happen regardless of smear or other issues in the data. We build the structure to spec.
        if len(data) != sect_size:
            vollog.error(
                f"Size of section data is {len(data)} expected {sect_size} for section {name} at address {address:#x}"
            )
            return None

        return data

    @classmethod
    def extract_module(
        cls,
        context: interfaces.context.ContextInterface,
        vmlinux_name: str,
        module: extensions.module,
    ) -> Optional[bytes]:
        # Bail early if bad address sent in
        try:
            hasattr(module.sect_attrs, "nsections")
        except exceptions.InvalidAddressException:
            vollog.debug(f"module at offset {module.vol.offset:#x} is paged out.")
            return None

        # Gather sections
        updated_sections, strtab_index, symtab_index = cls._parse_sections(
            context, vmlinux_name, module
        )

        kernel = context.modules[vmlinux_name]

        # Figure out header sizes
        if symbols.symbol_table_is_64bit(context, kernel.symbol_table_name):
            header_type = "Elf64_Ehdr"
            section_type = "Elf64_Shdr"
            bits = 64
        else:
            header_type = "Elf32_Ehdr"
            section_type = "Elf32_Shdr"
            bits = 32

        header_type_size = kernel.get_type(header_type).size
        section_type_size = kernel.get_type(section_type).size

        # Per Linux-spec, all LKMs must start with a null section header
        # This buffer is used to hold the headers as they are built
        sections_headers = b"\x00" * section_type_size

        # Holder of the data of the sections
        sections_data = b""

        # the .shstrtab section is "\x00" + section name for each section
        # followed by a terminating null.
        # It starts with the null string (\x00)
        shstrtab_data = b"\x00"

        # Track where we end the sections and data to glue `.shstrtab` after
        last_file_offset = None
        last_sect_size = None

        # Start at 1 in the string table
        name_index = 1

        # Create the actual section headers
        for index, (name, address, file_offset, section_data) in enumerate(
            updated_sections
        ):
            # Make the section header
            header_bytes = cls._make_section_header(
                bits,
                name_index,
                name,
                address,
                len(section_data),
                file_offset,
                strtab_index,
                symtab_index,
            )
            if not header_bytes:
                vollog.debug(f"make_section_header failed for section {name}")
                return None

            # ndex into the string table
            name_index += len(name) + 1

            # concatanate the header and section bytes
            sections_headers += header_bytes
            sections_data += section_data

            # track where we are so .shstrtab goes into correct offset
            last_file_offset = file_offset
            last_sect_size = len(section_data)

            # append each section name to what will become .shstrtab
            shstrtab_data += bytes(name, encoding="utf8") + b"\x00"

        # stick our own section reference string at end
        # name_index points to the end of the last section string after the loop ends
        shstrtab_data += b".shstrtab\x00"

        # create our .shstrtab section so sections have names
        sections_headers += cls._make_section_header(
            bits,
            name_index,
            ".shstrtab",
            0,
            len(shstrtab_data),
            last_file_offset + last_sect_size,
            strtab_index,
            symtab_index,
        )

        sections_data += shstrtab_data

        num_sections = len(updated_sections) + 1

        header = cls._make_elf_header(
            bits,
            header_type_size + len(sections_data),
            num_sections,
        )

        if not header:
            vollog.error(
                f"Hit error creating Elf header for module at {module.vol.offset:#x}"
            )
            return None

        # Return our beautiful, hand-crafted, farm raised ELF file
        return header + sections_data + sections_headers
