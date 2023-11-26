# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

from typing import Dict, Tuple

from volatility3.framework import constants
from volatility3.framework import objects, interfaces


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
        magic = self._context.object(
            symbol_table_name + constants.BANG + "unsigned long",
            layer_name=layer_name,
            offset=object_info.offset,
        )

        # Check validity
        if magic != 0x464C457F:
            return None

        # We need to read the EI_CLASS (0x4 offset)
        ei_class = self._context.object(
            symbol_table_name + constants.BANG + "unsigned char",
            layer_name=layer_name,
            offset=object_info.offset + 0x4,
        )

        if ei_class == 1:
            self._type_prefix = "Elf32_"
        elif ei_class == 2:
            self._type_prefix = "Elf64_"
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
        return self._type_prefix is not None and self._hdr is not None

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

    def _find_symbols(self):
        dt_strtab = None
        dt_symtab = None
        dt_strent = None

        for phdr in self.get_program_headers():
            try:
                # Find PT_DYNAMIC segment
                if str(phdr.p_type.description) != "PT_DYNAMIC":
                    continue
            except ValueError:
                # If the p_type value is outside the ones declared in the enumeration, an
                # exception is raised
                return None

            # This section contains pointers to the strtab, symtab, and strent sections
            for dsec in phdr.dynamic_sections():
                if dsec.d_tag == 5:
                    dt_strtab = dsec.d_ptr

                elif dsec.d_tag == 6:
                    dt_symtab = dsec.d_ptr

                elif dsec.d_tag == 11:
                    # Size of the symtab symbol entry
                    dt_strent = dsec.d_ptr

            break

        if dt_strtab is None or dt_symtab is None or dt_strent is None:
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

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._cached_strtab = None

    @property
    def cached_strtab(self):
        return self._cached_strtab

    @cached_strtab.setter
    def cached_strtab(self, cached_strtab):
        self._cached_strtab = cached_strtab

    def get_name(self):
        addr = self._cached_strtab + self.st_name

        # Just get the first 255 characters, it should be enough for a symbol name
        name_bytes = self._context.layers[self.vol.layer_name].read(addr, 255, pad=True)

        if name_bytes:
            idx = name_bytes.find(b"\x00")
            if idx != -1:
                name_bytes = name_bytes[:idx]
            return name_bytes.decode("utf-8", errors="ignore")
        else:
            # If we cannot read the name from the address space,
            # we return None.
            return None


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

        if self._parent_e_type == 3:  # ET_DYN
            offset = self._parent_offset + offset

        return offset

    def dynamic_sections(self):
        # sanity check
        try:
            if str(self.p_type.description) != "PT_DYNAMIC":
                return None
        except ValueError:
            # If the value is outside the ones declared in the enumeration, an
            # exception is raised
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


class_types = {
    "Elf": elf,
    "Elf64_Phdr": elf_phdr,
    "Elf32_Phdr": elf_phdr,
    "Elf32_Sym": elf_sym,
    "Elf64_Sym": elf_sym,
}
