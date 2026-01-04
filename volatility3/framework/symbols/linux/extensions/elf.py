# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

import logging
from typing import Dict, Optional, Tuple

from volatility3.framework import constants, exceptions, interfaces, objects
from volatility3.framework.constants import linux as linux_constants

vollog = logging.getLogger(__name__)


class elf(objects.StructType):
    """
    Class used to create elf objects. It overrides the typename to `Elf32_` or `Elf64_`,
    depending on the corresponding value on e_ident
    """

    def __init__(
        self,
        context: interfaces.context.ContextInterface,
        type_name: str,
        object_info: interfaces.objects.ObjectInformation,
        size: int,
        members: Dict[str, Tuple[int, interfaces.objects.Template]],
    ) -> None:
        super().__init__(
            context=context,
            type_name=type_name,
            object_info=object_info,
            size=size,
            members=members,
        )

        layer_name = self.vol.layer_name
        symbol_table_name = self.get_symbol_table_name()
        # We read the MAGIC: (0x0 to 0x4) 0x7f 0x45 0x4c 0x46
        try:
            magic = self._context.object(
                symbol_table_name + constants.BANG + "unsigned long",
                layer_name=layer_name,
                offset=object_info.offset,
            )
        except (
            exceptions.PagedInvalidAddressException,
            exceptions.InvalidAddressException,
        ) as excp:
            vollog.debug(
                f"Unable to check magic bytes for ELF file at offset {hex(object_info.offset)} in layer {layer_name}: {excp}"
            )
            return None

        # Check validity
        if magic != 0x464C457F:  # e.g. ELF
            return None

        # We need to read the EI_CLASS (0x4 offset)
        ei_class = self._context.object(
            symbol_table_name + constants.BANG + "unsigned char",
            layer_name=layer_name,
            offset=object_info.offset + linux_constants.ELF_IDENT.EI_CLASS,
        )

        if ei_class == linux_constants.ELF_CLASS.ELFCLASS32:
            self._type_prefix = "Elf32_"
            self._ei_class_size = 32
        elif ei_class == linux_constants.ELF_CLASS.ELFCLASS64:
            self._type_prefix = "Elf64_"
            self._ei_class_size = 64
        else:
            raise ValueError(f"Unsupported ei_class value {ei_class}")

        # Construct the full header
        self._hdr = self._context.object(
            symbol_table_name + constants.BANG + self._type_prefix + "Ehdr",
            layer_name=layer_name,
            offset=object_info.offset,
        )
        self._offset = object_info.offset

        self._cached_symtab = None
        self._cached_strtab = None

    def is_valid(self):
        """
        Determine whether it is a valid object
        """
        if hasattr(self, "_type_prefix") and hasattr(self, "_hdr"):
            return self._type_prefix is not None and self._hdr is not None
        else:
            return False

    def __getattr__(self, name):
        # Just redirect to the corresponding header
        if name[0:2] == "e_" and name in dir(self._hdr):
            return self._hdr.__getattr__(name)
        else:
            return self.__getattribute__(name)

    def __dir__(self):
        return self._hdr.__dir__() + [
            "get_program_headers",
            "is_valid",
            "get_section_headers",
            "get_symbols",
            "__dir__",
        ]

    def get_program_headers(self):
        program_headers = self._context.object(
            self.get_symbol_table_name() + constants.BANG + "array",
            layer_name=self.vol.layer_name,
            offset=self._offset + self.e_phoff,
            subtype=self._context.symbol_space.get_type(
                self.get_symbol_table_name()
                + constants.BANG
                + self._type_prefix
                + "Phdr"
            ),
            count=self.e_phnum,
        )

        for prog_header in program_headers:
            prog_header.parent_e_type = self.e_type
            prog_header.parent_offset = self._offset
            prog_header.type_prefix = self._type_prefix
            yield prog_header

    def get_section_headers(self):
        section_headers = self._context.object(
            self.get_symbol_table_name() + constants.BANG + "array",
            layer_name=self.vol.layer_name,
            offset=self._offset + self.e_shoff,
            subtype=self._context.symbol_space.get_type(
                self.get_symbol_table_name()
                + constants.BANG
                + self._type_prefix
                + "Shdr"
            ),
            count=self.e_shnum,
        )
        return section_headers

    def get_link_maps(self, kernel_symbol_table_name):
        """Get the ELF link map objects for the given VMA address

        Args:
            kernel_symbol_table_name (str): Kernel symbol table name

        Yields:
            The ELF link map objects
        """
        got_entry_size = self._ei_class_size // 8

        elf_symbol_table = self.get_symbol_table_name()

        link_maps_seen = set()
        for phdr in self.get_program_headers():
            try:
                if phdr.p_type.description != "PT_DYNAMIC":
                    continue
            except ValueError:
                vollog.log(
                    constants.LOGLEVEL_VVVV,
                    f"Skipping unknown ELF program header type: {phdr.p_type}",
                )
                continue

            for dsec in phdr.dynamic_sections():
                try:
                    if dsec.d_tag.description != "DT_PLTGOT":
                        continue
                except ValueError:
                    vollog.log(
                        constants.LOGLEVEL_VVVV,
                        f"Skipping unknown ELF dynamic section type: {dsec.d_tag}",
                    )
                    continue

                got_start = dsec.d_ptr

                # link_map is stored at the second GOT entry
                link_map_addr = got_start + got_entry_size

                # It needs the kernel symbol table to create a pointer
                link_map_ptr = self._context.object(
                    kernel_symbol_table_name + constants.BANG + "pointer",
                    offset=link_map_addr,
                    layer_name=self.vol.layer_name,
                )
                if not link_map_ptr:
                    vollog.log(
                        constants.LOGLEVEL_VVVV,
                        f"Invalid ELF link map pointer at 0x{link_map_addr:x}",
                    )
                    continue

                linkmap_symname = (
                    elf_symbol_table + constants.BANG + self._type_prefix + "LinkMap"
                )
                try:
                    link_map = self._context.object(
                        object_type=linkmap_symname,
                        offset=link_map_ptr,
                        layer_name=self.vol.layer_name,
                    )
                except exceptions.InvalidAddressException:
                    vollog.log(
                        constants.LOGLEVEL_VVVV,
                        f"Invalid ELF link map address at 0x{link_map_ptr:x}",
                    )
                    continue

                while link_map and link_map.vol.offset != 0:
                    if link_map.vol.offset in link_maps_seen:
                        break
                    link_maps_seen.add(link_map.vol.offset)

                    yield link_map

                    try:
                        link_map = self._context.object(
                            object_type=linkmap_symname,
                            offset=link_map.l_next,
                            layer_name=self.vol.layer_name,
                        )
                    except exceptions.InvalidAddressException:
                        vollog.log(
                            constants.LOGLEVEL_VVVV,
                            f"ELF link map linked list is corrupt at 0x{self.vol.offset:x}",
                        )
                        break

    def _find_symbols(self):
        dt_strtab = None
        dt_symtab = None
        dt_strent = None

        for phdr in self.get_program_headers():
            # Find PT_DYNAMIC segment
            try:
                if phdr.p_type.description != "PT_DYNAMIC":
                    continue
            except ValueError:
                vollog.log(
                    constants.LOGLEVEL_VVVV,
                    f"Skipping unknown ELF program header type: {phdr.p_type}",
                )
                continue

            # This section contains pointers to the strtab, symtab, and strent sections
            for dsec in phdr.dynamic_sections():
                try:
                    dtag = dsec.d_tag.description
                except ValueError:
                    vollog.log(
                        constants.LOGLEVEL_VVVV,
                        f"Skipping unknown ELF dynamic section type: {dsec.d_tag}",
                    )
                    continue

                if dtag == "DT_STRTAB":
                    dt_strtab = dsec.d_ptr

                elif dtag == "DT_SYMTAB":
                    dt_symtab = dsec.d_ptr

                elif dtag == "DT_SYMENT":
                    # Size of the symtab symbol entry
                    dt_strent = dsec.d_ptr

            break

        if not (dt_strtab and dt_symtab and dt_strent):
            return None

        self._cached_symtab = dt_symtab
        self._cached_strtab = dt_strtab

        # Calculate number of symbol entries assuming that strtab follows symtab
        if dt_symtab < dt_strtab:
            self._cached_numsyms = (dt_strtab - dt_symtab) // dt_strent
        else:
            self._cached_numsyms = 1024

    def get_symbols(self):
        if self._cached_symtab is None:
            self._find_symbols()

        if self._cached_symtab is None:
            return None

        symtab_arr = self._context.object(
            self.get_symbol_table_name() + constants.BANG + "array",
            layer_name=self.vol.layer_name,
            offset=self._cached_symtab,
            subtype=self._context.symbol_space.get_type(
                self.get_symbol_table_name()
                + constants.BANG
                + self._type_prefix
                + "Sym"
            ),
            count=self._cached_numsyms,
        )

        for sym in symtab_arr:
            sym.cached_strtab = self._cached_strtab
            yield sym


class elf_sym(objects.StructType):
    """An elf symbol entry"""

    _MAX_NAME_LENGTH = linux_constants.KSYM_NAME_LEN

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._cached_strtab = None

    @property
    def cached_strtab(self):
        return self._cached_strtab

    @cached_strtab.setter
    def cached_strtab(self, cached_strtab):
        self._cached_strtab = cached_strtab

    def get_name(self) -> Optional[str]:
        """Returns the symbol name"""

        try:
            addr = self._cached_strtab + self.st_name
        except exceptions.InvalidAddressException:
            return None

        layer = self._context.layers[self.vol.layer_name]
        name_bytes = layer.read(addr, self._MAX_NAME_LENGTH, pad=True)
        if not name_bytes:
            return None

        idx = name_bytes.find(b"\x00")
        if idx != -1:
            name_bytes = name_bytes[:idx]

        return name_bytes.decode("utf-8", errors="replace")


class elf_phdr(objects.StructType):
    """An elf program header"""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._parent_e_type = None
        self._parent_offset = None
        self._type_prefix = None

    @property
    def parent_e_type(self):
        return self._parent_e_type

    @parent_e_type.setter
    def parent_e_type(self, e_type):
        self._parent_e_type = e_type

    @property
    def parent_offset(self):
        return self._parent_offset

    @parent_offset.setter
    def parent_offset(self, offset):
        self._parent_offset = offset

    @property
    def type_prefix(self):
        return self._type_prefix

    @type_prefix.setter
    def type_prefix(self, prefix):
        self._type_prefix = prefix

    def get_vaddr(self):
        offset = self.__getattr__("p_vaddr")

        try:
            if self._parent_e_type.description == "ET_DYN":
                offset = self._parent_offset + offset
        except ValueError:
            # Unknown ELF object file type. Anyway, if the ELF object file type is not a
            # shared object (ET_DYN), the virtual address is 'p_vaddr'.
            vollog.log(
                constants.LOGLEVEL_VVVV,
                f"Skipping unknown ELF object type: {self._parent_e_type}",
            )

        return offset

    def dynamic_sections(self):
        # sanity check
        try:
            if self.p_type.description != "PT_DYNAMIC":
                return None
        except ValueError:
            # If the value is outside the ones declared in the enumeration, an
            # exception is raised
            vollog.log(
                constants.LOGLEVEL_VVVV,
                f"Skipping unknown ELF program header type: {self.p_type}",
            )
            return None

        # the buffer of array starts at elf_base + our virtual address ( offset )
        arr_start = self.get_vaddr()

        symbol_table_name = self.get_symbol_table_name()

        rtsize = self._context.symbol_space.get_type(
            symbol_table_name + constants.BANG + self._type_prefix + "Dyn"
        ).size

        for i in range(256):
            # use the real size
            idx = i * rtsize

            dyn = self._context.object(
                symbol_table_name + constants.BANG + self._type_prefix + "Dyn",
                layer_name=self.vol.layer_name,
                offset=arr_start + idx,
            )

            yield dyn

            if dyn.d_tag == 0:
                break


class elf_linkmap(objects.StructType):
    def get_name(self):
        try:
            buf = self._context.layers.read(self.vol.layer_name, self.l_name, 256)
        except exceptions.InvalidAddressException:
            # Protection against memory smear
            vollog.log(
                constants.LOGLEVEL_VVVV,
                f"Invalid l_name address for ELF link map at 0x{self.vol.offset:x}",
            )
            return None

        idx = buf.find(b"\x00")
        if idx != -1:
            buf = buf[:idx]
        return buf.decode("utf-8", errors="replace")


class_types = {
    "Elf": elf,
    "Elf64_Phdr": elf_phdr,
    "Elf32_Phdr": elf_phdr,
    "Elf32_Sym": elf_sym,
    "Elf64_Sym": elf_sym,
    "Elf32_LinkMap": elf_linkmap,
    "Elf64_LinkMap": elf_linkmap,
}
