# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

from volatility.framework.symbols import intermed
from volatility.framework.symbols.linux.extensions import elf 


class ElfIntermedSymbols(intermed.IntermediateSymbolTable):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.set_type_class('Elf', elf.elf)
        self.set_type_class('Elf64_Phdr', elf.elf_phdr)
        self.set_type_class('Elf32_Phdr', elf.elf_phdr)
        self.set_type_class('Elf32_Sym', elf.elf_sym)
        self.set_type_class('Elf64_Sym', elf.elf_sym)
