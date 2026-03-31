# This file is Copyright 2025 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
import dataclasses
import functools
import logging
from typing import Iterator, List, Optional, Tuple

import volatility3.framework.symbols.linux.utilities.modules as linux_utilities_modules
from volatility3.framework import constants, exceptions, interfaces
from volatility3.framework.configuration import requirements
from volatility3.framework.constants import linux as linux_constants
from volatility3.framework.objects import utility
from volatility3.framework.symbols import linux

vollog = logging.getLogger(__name__)


@dataclasses.dataclass
class KASConfig:
    """Kallsyms configuration class"""

    num_syms_address: int
    names_address: int
    token_table_address: int
    token_index_address: int
    offsets_address: int
    relative_base_address: int
    _stext: int

    # Usually not in VMCOREINFO, these are found during the bootstrap stage.
    # If an ISF is available, they are fetched from there instead.
    markers_address: int = None
    addresses_address: int = None
    _sinittext: int = None
    _einittext: int = None
    _etext: int = None
    _end: int = None
    mod_tree: int = None
    module_addr_min: int = None
    module_addr_max: int = None
    start_ksymtab: int = None
    stop_ksymtab: int = None
    bpf_tree_address: int = None
    seqs_of_names_address: int = None

    num_syms_type_size: int = None
    markers_type_size: int = None
    kernel_symbol_size: int = None

    @classmethod
    def _get_symbol_address(cls, context, layer_name, module_name, symbol_name):
        vmlinux = context.modules[module_name]
        if not vmlinux.has_symbol(symbol_name):
            return None

        layer = context.layers[layer_name]
        address = vmlinux.get_symbol(symbol_name).address
        address += layer.config["kernel_virtual_offset"]
        return address

    @classmethod
    def new_from_isf(cls, context, layer_name, module_name):
        vmlinux = context.modules[module_name]

        # kallsyms_num_syms and kallsyms_markers types were updated from a unsigned long
        # to unsigned int in 4.20 80ffbaa5b1bd98e80e3239a3b8cfda2da433009a
        num_syms_type_size = vmlinux.get_symbol("kallsyms_num_syms").type.size
        kernel_symbol_size = vmlinux.get_type("kernel_symbol").size

        def get_symbol_address(symbol_name):
            return cls._get_symbol_address(
                context, layer_name, module_name, symbol_name
            )

        kas_config = KASConfig(
            num_syms_address=get_symbol_address("kallsyms_num_syms"),
            names_address=get_symbol_address("kallsyms_names"),
            token_table_address=get_symbol_address("kallsyms_token_table"),
            token_index_address=get_symbol_address("kallsyms_token_index"),
            offsets_address=get_symbol_address("kallsyms_offsets"),
            relative_base_address=get_symbol_address("kallsyms_relative_base"),
            markers_address=get_symbol_address("kallsyms_markers"),
            addresses_address=get_symbol_address("kallsyms_addresses"),
            _sinittext=get_symbol_address("_sinittext"),
            _einittext=get_symbol_address("_einittext"),
            _stext=get_symbol_address("_stext"),
            _etext=get_symbol_address("_etext"),
            _end=get_symbol_address("_end"),
            mod_tree=get_symbol_address("mod_tree"),
            module_addr_min=get_symbol_address("module_addr_min"),
            module_addr_max=get_symbol_address("module_addr_max"),
            start_ksymtab=get_symbol_address("__start___ksymtab"),
            stop_ksymtab=get_symbol_address("__stop___ksymtab"),
            bpf_tree_address=get_symbol_address("bpf_tree"),
            seqs_of_names_address=get_symbol_address("kallsyms_seqs_of_names"),
            num_syms_type_size=num_syms_type_size,
            markers_type_size=num_syms_type_size,
            kernel_symbol_size=kernel_symbol_size,
        )
        return kas_config


class _KallsymsIO:
    """Helper to interpret a memory address as a file pointer.

    For internal use within the Kallsyms API; external use is discouraged.
    """

    def __init__(
        self,
        context: interfaces.context.ContextInterface,
        layer_name: str,
        base=0,
        endian="little",
    ):
        self._context = context
        self._layer_name = layer_name
        self._base = base
        self._position = base
        self._endian = endian

    def read(self, size: int) -> bytes:
        """Return 'size' bytes from the current position"""
        layer = self._context.layers[self._layer_name]
        buf = layer.read(offset=self._position, length=size)
        self._position += size
        return buf

    def read_str(self, size: int) -> str:
        """Returns 'size' bytes as a string from the current position."""
        return self.read(size).decode()

    def read_int(self, size: int, signed: bool = False) -> int:
        """Returns the integer stored in the current position using 'size' bytes.
        Args:
            size: Number of bytes to use for the int.
            signed: Integer sign.

        Returns:
            The integer stored in the current position.
        """
        return int.from_bytes(
            self.read(size),
            byteorder=self._endian,
            signed=signed,
        )

    def seek(self, offset: int) -> None:
        """Seek the pointer to the given offset, based on the base address.

        Args:
            offset: offset from the base address
        """
        self._position = self._base + offset


@dataclasses.dataclass
class KASSymbolBasic:
    name: str
    type: str


@dataclasses.dataclass
class KASSymbol(KASSymbolBasic):
    address: int
    size: int
    module_name: str
    exported: bool = False
    subsystem: str = None

    def __str__(self):
        return (
            f"name:{self.name}, type:{self.type}, address:{self.address:#x}, "
            f"size:{self.size}, exported:{self.exported}, subsystem:{self.subsystem}"
        )

    def set_exported_from_type(self) -> None:
        """Updates the 'export' member based on the symbol's type.

        This method evaluates the symbol's type and sets the 'export' member
        to indicate whether the object is exported. This code and Linux kernel follows
        the nm symbol type logic.
        """
        # As per the "nm" man page:
        # If lowercase, the symbol is usually local; if uppercase, the symbol is
        # global (external). There are however a few lowercase symbols that are shown
        # for special global symbols ("u", "v" and "w").
        if self.type:
            self.exported = bool(self.type.isupper() or self.type in ("u", "v", "w"))
        else:
            self.exported = None

    @functools.cached_property
    def type_description(self) -> Optional[str]:
        """Returns the interpreted meaning of the symbol type based on the nm tool.

        Returns:
            A string with the type description.
        """
        # If a symbol type exists with the original case, get it
        symbol_type_description = linux_constants.NM_TYPES_DESC.get(self.type, None)
        if symbol_type_description:
            return symbol_type_description

        if self.type:
            # Otherwise, use the lowercase version
            symbol_type_description = linux_constants.NM_TYPES_DESC.get(
                self.type.lower(), None
            )

        return symbol_type_description


@dataclasses.dataclass
class KASFilter:
    name: str
    type: str


class Kallsyms(interfaces.configuration.VersionableInterface):
    """Kallsyms API class"""

    _required_framework_version = (2, 19, 0)
    _version = (1, 0, 0)

    # Internal kernel core constants
    _CORE_SUBSYSTEM_NAME = "core"
    _CORE_MODULE_NAME = "kernel"

    # Internal module constants
    _MODULE_SUBSYSTEM_NAME = "module"

    # Internal FTrace constants
    _FTRACE_SUBSYSTEM_NAME = "ftrace"
    _FTRACE_MODULE_SYM_TYPE = "T"
    _FTRACE_TRAMPOLINE_MODULE_NAME = "__builtin__ftrace"
    _FTRACE_TRAMPOLINE_SYM = "ftrace_trampoline"
    _FTRACE_TRAMPOLINE_SYM_TYPE = "t"

    # Internal BPF constants
    _BPF_SUBSYSTEM_NAME = "bpf"
    _BPF_MODULE_NAME = "bpf"
    _BPF_SYM_TYPE = "t"

    def __init__(
        self,
        context: interfaces.context.ContextInterface,
        layer_name: str,
        module_name: str,
        kas_config: KASConfig = None,
        progress_callback: constants.ProgressCallback = None,
    ) -> None:
        """Initialize the Kallsyms API

        Args:
            context: The context used to access memory layers and symbols
            layer_name: The name of layer within the context in which the module exists
            module_name: The name of the kernel module on which to operate
            kas_config: The KAllSyms configuration
            progress_callback: Method that is called periodically during scanning to
                update progress
        """
        super().__init__()

        self._assert_versions()

        self._context = context
        self._layer_name = layer_name
        self._module_name = module_name
        self._kas_config = kas_config
        self._progress_callback = progress_callback
        if progress_callback and not callable(progress_callback):
            raise TypeError("Progress_callback is not callable")

        if not kas_config:
            self._kas_config = KASConfig.new_from_isf(
                context=context,
                layer_name=layer_name,
                module_name=module_name,
            )

        layer = self._context.layers[self._layer_name]
        # FIXME: The layer lacks this information. Could there be a better alternative?
        self._endian = "little" if layer._entry_format[0] == "<" else "big"
        self._long_size = layer.bits_per_register // 8

        self._kallsyms_num_syms = None
        self._kallsyms_relative_base = None

        self._kallsyms_token_index_address = None
        self._kallsyms_offsets_address = None
        self._kallsyms_names_io = _KallsymsIO(
            context=self._context,
            layer_name=self._layer_name,
            base=self._kas_config.names_address,
            endian=self._endian,
        )

        self._kallsyms_token_table_io = _KallsymsIO(
            context=self._context,
            layer_name=self._layer_name,
            base=self._kas_config.token_table_address,
            endian=self._endian,
        )

        self._bootstrap()

    @classmethod
    def _assert_versions(cls) -> None:
        """Verify versions of shared dependencies"""
        linux_utilities_modules_version_required = (3, 0, 0)
        if not requirements.VersionRequirement.matches_required(
            linux_utilities_modules_version_required,
            linux_utilities_modules.Modules.version,
        ):
            raise exceptions.VolatilityException(
                "linux_utilities_modules.Modules version not suitable: "
                f"required {linux_utilities_modules_version_required} found {linux_utilities_modules.Modules.version}",
            )

        return None

    def _read_bytes(self, address: int, size: int) -> Optional[bytes]:
        layer = self._context.layers[self._layer_name]
        try:
            return layer.read(address, size).decode()
        except exceptions.InvalidAddressException:
            return None

    def _read_int(self, address: int, size: int, signed: bool = False) -> Optional[int]:
        layer = self._context.layers[self._layer_name]
        try:
            return int.from_bytes(
                layer.read(address, size),
                byteorder=self._endian,
                signed=signed,
            )
        except exceptions.InvalidAddressException:
            return None

    def _bootstrap(self) -> None:
        layer = self._context.layers[self._layer_name]
        # kallsyms_num_syms and kallsyms_markers[] types were updated from a unsigned long
        # to unsigned int in 4.20 80ffbaa5b1bd98e80e3239a3b8cfda2da433009a
        self._kallsyms_num_syms = self._read_int(
            self._kas_config.num_syms_address,
            self._kas_config.num_syms_type_size,
            signed=False,
        )

        if self._kas_config.relative_base_address:
            # kernels >= 4.6
            self._kallsyms_relative_base = (
                self._read_int(
                    self._kas_config.relative_base_address,
                    self._long_size,
                    signed=False,
                )
                & layer.address_mask
            )

        self._kallsyms_offsets_address = self._kas_config.offsets_address
        self._kallsyms_token_index_address = self._kas_config.token_index_address

        # Preload the kallsyms_token_index array
        short_size = 2
        self._kallsyms_token_index = [
            self._read_int(
                self._kallsyms_token_index_address + index * short_size,
                short_size,
                signed=False,
            )
            for index in range(256)
        ]

    def _get_symbol(
        self,
        offset,
        index,
        filters: List[KASFilter] = None,
    ) -> Optional[Tuple[KASSymbol, int]]:
        kassymbolbasic, compressed_length = self._expand_symbol(offset, filters)
        kassymbol = None
        if kassymbolbasic:
            sym_addr = self._get_symbol_address_by_index(index=index)
            _, sym_size = self._get_symbol_pos(sym_addr)

            kassymbol = KASSymbol(
                name=kassymbolbasic.name,
                type=kassymbolbasic.type,
                address=sym_addr,
                size=sym_size,
                module_name=self._CORE_MODULE_NAME,
                subsystem=self._CORE_SUBSYSTEM_NAME,
            )
            kassymbol.set_exported_from_type()
        return kassymbol, compressed_length

    def get_core_symbols(
        self,
        progress_callback: constants.ProgressCallback = None,
    ) -> Iterator[KASSymbol]:
        """Yield each kernel core symbol

        Args:
            progress_callback: Method that is called periodically during scanning to
                update progress

        Based on kallsyms_on_each_symbol()

        Yields:
            KASSymbol objects
        """
        current_offset = 0
        for sym_idx in range(self._kallsyms_num_syms):
            try:
                kassymbol, compressed_length = self._get_symbol(current_offset, sym_idx)
            except exceptions.InvalidAddressException:
                vollog.debug(
                    f"Unable to reconstruct core symbol at offset {current_offset:#x} and index {sym_idx}"
                )
                continue

            if compressed_length is None:
                vollog.debug(
                    f"Unable to reconstruct compressed_length at offset {current_offset:#x} and index {sym_idx}"
                )
                break

            if kassymbol:
                yield kassymbol

            if progress_callback:
                progress_callback(
                    (sym_idx / self._kallsyms_num_syms) * 100,
                    "Populating Kallsyms core symbols",
                )

            current_offset += compressed_length + 1

    def _expand_symbol(
        self,
        offset: int,
        filters: List[KASFilter] = None,
    ) -> Tuple[KASSymbolBasic, int]:
        """Expand a compressed symbol using its offset in the stream
        Based on kallsyms_expand_symbol()

        Args:
            offset: Symbol offset in the kallsyms arrays.
            filters: List of KASFilter filters

        Returns:
            A tuple with a KASSymbolBasic object and the symbol name's compressed length.
        """
        filters = filters if filters is not None else []
        type_filters = tuple(kassymbolfilter.type for kassymbolfilter in filters)

        self._kallsyms_names_io.seek(offset)
        # The compressed symbol length is in the first byte
        compressed_length = self._kallsyms_names_io.read_int(size=1)
        if compressed_length & 0x80 != 0:
            # kernels >= 6.1 73bbb94466fd3f8b313eeb0b0467314a262dddb3
            # MSB 1 means a 'big' symbol, we need an extra byte
            lower_byte = compressed_length
            upper_byte = self._kallsyms_names_io.read_int(size=1)
            compressed_length = (upper_byte << 7) | (lower_byte & 0x7F)

        abort_decompression = False
        sym_type = None
        sym_name = ""
        for _ in range(compressed_length):
            token_index_index = self._kallsyms_names_io.read_int(size=1)
            token_index = self._kallsyms_token_index[token_index_index]
            self._kallsyms_token_table_io.seek(token_index)
            token = self._kallsyms_token_table_io.read_str(1)
            while token != "\x00":
                if not sym_type:
                    sym_type = token
                    # We got the symbol type, we can abort this immediatelly
                    if type_filters and sym_type not in type_filters:
                        abort_decompression = True
                        break
                else:
                    sym_name += token
                    for kassymbolfilter in filters:
                        if kassymbolfilter.type is not None:
                            if (
                                sym_type == kassymbolfilter.type
                                and kassymbolfilter.name.startswith(sym_name)
                            ):
                                break
                        elif kassymbolfilter.name.startswith(sym_name):
                            break

                    else:
                        if filters:
                            abort_decompression = True

                token = self._kallsyms_token_table_io.read_str(1)

            if abort_decompression:
                break

        kassymbolbasic = (
            KASSymbolBasic(name=sym_name, type=sym_type)
            if not abort_decompression
            else None
        )
        return kassymbolbasic, compressed_length

    def _get_symbol_address_by_index(self, index: int) -> Optional[int]:
        """Return symbol address based on the symbol index in the kallsyms arrays.
        Based on kallsyms_sym_address()

        Args:
            index: Symbol index

        Returns:
            Symbol address
        """
        layer = self._context.layers[self._layer_name]
        if self._kallsyms_offsets_address:
            # kernels >= 4.6 - Addresses are relative to kallsyms_relative_base
            # It assumes: CONFIG_KALLSYMS_BASE_RELATIVE=y and CONFIG_KALLSYMS_ABSOLUTE_PERCPU=y
            signed_int_size = 4
            sym_offset_ptr = self._kallsyms_offsets_address + (index * signed_int_size)
            sym_addr = self._read_int(sym_offset_ptr, signed_int_size, signed=True)
            if sym_addr is None:
                return None

            if sym_addr < 0:
                # Negative offsets are relative to kallsyms_relative_base - 1
                return self._kallsyms_relative_base - 1 - sym_addr

            # Positive offsets are absolute values
            return sym_addr & layer.address_mask
        elif self._kas_config.addresses_address:
            # kernels < 4.6 - Addresses are absolute
            # unsigned long kallsyms_addresses[]
            kallsyms_address = self._read_int(
                self._kas_config.addresses_address + (index * self._long_size),
                self._long_size,
                signed=False,
            )
            if kallsyms_address is None:
                return None

            return kallsyms_address & layer.address_mask
        else:
            raise exceptions.VolatilityException("Unsupported kernel")

    @functools.lru_cache
    def _get_symbol_pos(self, address: int) -> Optional[Tuple[int, int]]:
        """Returns the symbol position in the kallsyms arrays and its size."""
        low = 0
        high = self._kallsyms_num_syms

        while high - low > 1:
            mid = low + (high - low) // 2
            symbol_index = self._get_symbol_address_by_index(mid)
            if symbol_index is None:
                return None, None
            elif symbol_index <= address:
                low = mid
            else:
                high = mid

        # prevent accidental bleed through
        symbol_index = None

        # Search for the first aliased symbol. *Aliased symbols* are symbols with the same address.
        while low:
            symbol_index = self._get_symbol_address_by_index(low - 1)
            if symbol_index is None:
                return None, None

            if symbol_index == self._get_symbol_address_by_index(low):
                low -= 1
            else:
                break

        symbol_start = self._get_symbol_address_by_index(low)
        if symbol_start is None:
            return None, None

        symbol_end = 0

        # Search for next non-aliased symbol.
        for idx in range(low + 1, self._kallsyms_num_syms):
            symbol_index = self._get_symbol_address_by_index(idx)
            if symbol_index is None:
                return None, None

            if symbol_index > symbol_start:
                symbol_end = self._get_symbol_address_by_index(idx)
                break

        # pylint: disable=protected-access
        # If no next symbol is found, we default to using the end of the section
        if not symbol_end:
            if self._is_kernel_inittext(address):
                symbol_end = self._kas_config._einittext
            elif self._kas_config._end is not None:
                # Assume CONFIG_KALLSYMS_ALL=y. Otherwise, symbol_end will be _etext
                symbol_end = self._kas_config._end
            else:
                symbol_end = self._kas_config._etext

        symbol_size = symbol_end - symbol_start

        return low, symbol_size

    @functools.lru_cache
    def _get_symbol_offset(self, index: int) -> int:
        """Find the offset on the compressed stream given the index in the kallsyms array.

        Based on get_symbol_offset

        Returns:
            Offset on the compressed stream
        """

        # Use the nearest marker, placed every 256 positions
        kallsyms_markers_pos_ptr = (
            self._kas_config.markers_address
            + (index >> 8) * self._kas_config.markers_type_size
        )
        kallsyms_markers_pos = self._read_int(
            kallsyms_markers_pos_ptr, self._kas_config.markers_type_size, signed=False
        )
        name_addr = self._kas_config.names_address + kallsyms_markers_pos

        # Scan symbols sequentially until the target. Each symbol uses a
        # [<len>][<len> bytes of data] format, so we skip symbols by adding their length
        # to the pointer value.
        for _ in range(index & 0xFF):
            compressed_length = self._read_int(name_addr, 1)
            if compressed_length & 0x80 != 0:
                # kernels >= 6.1 73bbb94466fd3f8b313eeb0b0467314a262dddb3
                # MSB 1 means a 'big' symbol, we need an extra byte
                lower_byte = compressed_length
                upper_byte = self._kallsyms_names_io.read_int(size=1)
                compressed_length = (upper_byte << 7) | (lower_byte & 0x7F)

            name_addr += compressed_length + 1

        return name_addr - self._kas_config.names_address

    def _is_kernel_inittext(self, addr: int) -> bool:
        # pylint: disable=protected-access
        if not (self._kas_config._sinittext and self._kas_config._einittext):
            # We don't know
            return False

        return self._kas_config._sinittext <= addr < self._kas_config._einittext

    def _is_kernel_text(self, addr: int) -> bool:
        # pylint: disable=protected-access
        return self._kas_config._stext <= addr < self._kas_config._etext

    def _is_core_ksym_addr(self, addr: int) -> bool:
        return self._is_kernel_text(addr) or self._is_kernel_inittext(addr)

    def lookup_address(self, address: int) -> Optional[KASSymbol]:
        """Search for a symbol by its memory address.

        This function scans kernel core, module symbols, BPF symbols, and Ftrace symbols
        to locate the first symbol matching the specified address. Note that multiple
        symbols (aliased symbols) can share the same memory address, so this method
        returns the first match found.

        Based on kallsyms_lookup.

        Args:
            address: The memory address to search for.

        Returns:
            The matching symbol if found, or None if no match is found.
        """
        layer = self._context.layers[self._layer_name]
        address &= layer.address_mask

        kassymbol = self.core_lookup_address(address)
        if not kassymbol:
            kassymbol = self.module_lookup_address(address)

        if not kassymbol:
            kassymbol = self.bpf_lookup_address(address)

        if not kassymbol:
            kassymbol = self.ftrace_lookup_address(address)

        return kassymbol

    def core_lookup_address(self, address: int) -> Optional[KASSymbol]:
        """Search for a symbol by its memory address within the kernel core.

        Based on kallsyms_lookup_buildid.

        Args:
            address: The memory address to search for.

        Returns:
            The matching symbol if found, or None if no match is found.
        """
        layer = self._context.layers[self._layer_name]
        address &= layer.address_mask

        if not self._is_core_ksym_addr(address):
            return None

        pos, sym_size = self._get_symbol_pos(address)
        if pos is None:
            return None
        offset = self._get_symbol_offset(pos)
        sym_address = self._get_symbol_address_by_index(pos)
        kassymbolbasic, _compressed_length = self._expand_symbol(offset)

        if not kassymbolbasic:
            return None

        kas_symbol = KASSymbol(
            name=kassymbolbasic.name,
            type=kassymbolbasic.type,
            address=sym_address,
            size=sym_size,
            module_name=self._CORE_MODULE_NAME,
            subsystem=self._CORE_SUBSYSTEM_NAME,
        )
        kas_symbol.set_exported_from_type()
        return kas_symbol

    def _is_symbol_exported(
        self,
        name: int,
        address: int,
        module: Optional[interfaces.objects.ObjectInterface] = None,
    ) -> bool:
        """Check if the address belongs to an exported symbol.
        If a module object is provided, it searches in that module symbols.
        Otherwise, it searches in the global symbols.

        Bases on is_exported

        Args:
            name: Symbol name
            address: Symbol address
            module: Module object. Defaults to None.

        Returns:
            True if the symbol is exported; otherwise, returns False
        """
        if module:
            if module.num_syms <= 0:
                return False

            start_mod_ksymtab = module.syms
            stop_mod_ksymtab = (
                start_mod_ksymtab
                + module.num_syms * self._kas_config.kernel_symbol_size
            )
            kernel_symbol = self._find_exported_symbol_in_range(
                name, start_mod_ksymtab, stop_mod_ksymtab
            )
        else:
            # Search the not GPL modules
            kernel_symbol = self._find_exported_symbol_in_range(
                name,
                self._kas_config.start_ksymtab,
                self._kas_config.stop_ksymtab,
            )

        if kernel_symbol is not None:
            if hasattr(kernel_symbol, "get_value"):
                return kernel_symbol.get_value() == address
            else:
                return kernel_symbol.vol.offset == address

        return None

    def _elfsym_to_kassymbol(
        self,
        module: interfaces.objects.ObjectInterface,
        elf_sym_obj: interfaces.objects.ObjectInterface,
        elf_sym_index: int,
        subsystem: str = None,
    ) -> Optional[KASSymbol]:
        """Returns a KASSymbol from a ElfSym

        Args:
            module: Module object
            elf_sym_obj: ElfSym object
            elf_sym_index: ElfSym index
            subsystem: Name of the sub-subtem: core, module, bpf, ftrace, etc

        Returns:
            A KASSymbol object
        """
        layer = self._context.layers[self._layer_name]
        sym_name = elf_sym_obj.get_name()
        if not sym_name:
            return None

        # Normalize sym.st_value offset, which is an address pointing to the symbol value
        sym_address = elf_sym_obj.st_value & layer.address_mask
        sym_type = module.get_symbol_type(elf_sym_obj, elf_sym_index)

        kas_symbol = KASSymbol(
            name=sym_name,
            type=sym_type,
            address=sym_address,
            size=elf_sym_obj.st_size,
            module_name=module.get_name(),
            exported=False,
            subsystem=subsystem,
        )
        kas_symbol.set_exported_from_type()
        return kas_symbol

    def _is_module_ksym_address(self, address: int) -> bool:
        return self._modules_address_min <= address <= self._modules_address_max

    def module_lookup_address(
        self,
        address: int,
        module: Optional[interfaces.objects.ObjectInterface] = None,
    ) -> Optional[KASSymbol]:
        """Search for a symbol within kernel modules based on its memory address.
        If a module object is provided, it will only search in that module. Otherwise,
        it will try to first find the module to where the provided address belong to.

        Based on module_address_lookup.

        Args:
            address: The memory address of the symbol to search for
            module [optional]: The module to search within. If not provided, the module
                containing the address will be automatically determined

        Returns:
            The matching KASSymbol if found; otherwise, returns None
        """
        if not self._is_module_ksym_address(address):
            return None

        module = module or self._get_module_by_address(address)
        if not module:
            # This may occur if the kernel lacks the mod_tree implementation.
            for (
                cur_module,
                minimum_address,
                maximum_address,
            ) in self._module_memory_region:
                if minimum_address <= address < maximum_address:
                    module = cur_module
                    break

        if not module:
            # We couldn't find the module
            return None

        kassymbol = self._find_address_in_module_symbols(module, address)
        if kassymbol:
            return kassymbol

        return None

    def _find_address_in_module_symbols(
        self,
        module: interfaces.objects.ObjectInterface,
        address: int,
    ) -> Optional[KASSymbol]:
        """Find the symbol corresponding to a given address within a module.

        Based on find_kallsyms_symbol

        Args:
            module: The module where the address belongs to
            address: The memory address to search for

        Returns:
            The matching KASSymbol if found; otherwise, returns None
        """
        # Before walking all the symbols, ensure the address belongs to this module
        module_boundaries = module.get_module_address_boundaries()
        if not module_boundaries:
            return None

        minimum_address, maximum_address = module_boundaries
        if not (minimum_address <= address < maximum_address):
            return None

        layer = self._context.layers[self._layer_name]
        for elf_sym_idx, elf_sym in enumerate(module.get_symbols()):
            if not elf_sym.get_name():
                continue

            sym_address_start = elf_sym.st_value & layer.address_mask
            sym_address_end = sym_address_start + elf_sym.st_size

            if sym_address_start <= address < sym_address_end:
                return self._elfsym_to_kassymbol(
                    module, elf_sym, elf_sym_idx, subsystem=self._MODULE_SUBSYSTEM_NAME
                )

        return None

    @functools.cached_property
    def _module_memory_region(
        self,
    ) -> List[Tuple[interfaces.objects.ObjectInterface, int, int]]:
        modules_region = []
        for module in linux_utilities_modules.Modules.list_modules(
            self._context, self._module_name
        ):
            minimum_address, maximum_address = module.get_module_address_boundaries()
            module_region = module, minimum_address, maximum_address
            modules_region.append(module_region)

        return modules_region

    @functools.lru_cache
    def _get_modules_memory_boundaries(self) -> Tuple[int, int]:
        """Determine the boundaries of the module allocation area

        Returns:
            A tuple containing the minimum and maximum addresses for the kernel module
            allocation area.
        """

        if self._kas_config.mod_tree:
            # Kernel >= 5.19    58d208de3e8d87dbe196caf0b57cc58c7a3836ca
            mod_tree_address = self._kas_config.mod_tree
            vmlinux = self._context.modules[self._module_name]
            mod_tree = vmlinux.object(
                object_type="mod_tree_root",
                offset=mod_tree_address,
                absolute=True,
            )
            addr_min, addr_max = mod_tree.addr_min, mod_tree.addr_max
        elif self._kas_config.module_addr_min and self._kas_config.module_addr_max:
            # 2.6.27 <= kernel < 5.19   3a642e99babe0617febb6f402e1e063479f489db
            kas_config = self._kas_config
            addr_min, addr_max = kas_config.module_addr_min, kas_config.module_addr_max
        else:
            raise exceptions.VolatilityException(
                "Cannot find the module memory allocation area. Unsupported kernel"
            )

        layer = self._context.layers[self._layer_name]
        return addr_min & layer.address_mask, addr_max & layer.address_mask

    @functools.cached_property
    def _modules_address_min(self):
        address_min, _address_max = self._get_modules_memory_boundaries()
        return address_min

    @functools.cached_property
    def _modules_address_max(self):
        _address_min, address_max = self._get_modules_memory_boundaries()
        return address_max

    def _get_module_by_address(
        self, address: int
    ) -> Optional[interfaces.objects.ObjectInterface]:
        """Searches for the module that contains the given memory address within its range.
        It uses a latch tree for optimized address range searching.

            Based on __module_address()

        Args:
            address: The module memory address to search for.

        Returns:
            The matching module if found; otherwise, returns None
        """
        if not self._is_module_ksym_address(address):
            return None

        return self._search_module_by_address(address)

    @functools.lru_cache
    def _get_type_cache(self, name: str) -> Optional[interfaces.objects.Template]:
        vmlinux = self._context.modules[self._module_name]
        try:
            return vmlinux.get_type(name)
        except exceptions.SymbolError:
            return None

    def _mod_tree_comp(
        self, address: int, latch_tree_node: interfaces.objects.ObjectInterface
    ) -> Optional[int]:
        vmlinux = self._context.modules[self._module_name]

        module_memory_mtn = self._get_type_cache("module_memory")
        if not module_memory_mtn:
            vollog.debug(
                "`module_memory` symbol not present in the symbol table. Cannot proceed."
            )
            return None

        module_memory_mtn_offset = module_memory_mtn.relative_child_offset("mtn")

        mod_tree_node_mod = self._get_type_cache("mod_tree_node")
        if not mod_tree_node_mod:
            vollog.debug(
                "`mod_tree_node` symbol not present in the symbol table. Cannot proceed."
            )
            return None

        mod_tree_node_mod_offset = mod_tree_node_mod.relative_child_offset("mod")

        module_memory_offset = (
            latch_tree_node.vol.offset
            + module_memory_mtn_offset
            + mod_tree_node_mod_offset
        )

        module_memory = vmlinux.object(
            object_type="module_memory",
            offset=module_memory_offset,
            absolute=True,
        )
        start = module_memory.base
        end = start + module_memory.size

        if address < start:
            return -1
        elif address >= end:
            return 1
        else:
            return 0

    def _search_module_by_address(
        self, address: int
    ) -> Optional[interfaces.objects.ObjectInterface]:
        """Searches for the module that contains the given memory address within its range.
        It uses a latch tree for optimized address range searching.

            Based on mod_find

        Args:
            address: The module memory address to search for

        Returns:
            The matching module if found; otherwise, returns None
        """
        vmlinux = self._context.modules[self._module_name]
        if self._kas_config.mod_tree:
            mod_tree_address = self._kas_config.mod_tree
            mod_tree = vmlinux.object(
                object_type="mod_tree_root",
                offset=mod_tree_address,
                absolute=True,
            )
            latch_tree_root = mod_tree.root
            latch_tree_node = latch_tree_root.find(address, self._mod_tree_comp)
            if latch_tree_node:
                mod_tree_node = linux.LinuxUtilities.container_of(
                    latch_tree_node.vol.offset, "mod_tree_node", "node", vmlinux
                )
                module_ptr = mod_tree_node.mod
                if not module_ptr.is_readable():
                    vollog.warning("Modules latch tree seems corrupt")
                    return None

                return module_ptr.dereference()

        return None

    def _find_exported_symbol_in_range(
        self, name: str, start: int, stop: int
    ) -> Optional[interfaces.objects.ObjectInterface]:
        """Find an exported symbol within a specified range of kernel symbols.

        Based on lookup_exported_symbol

        Args:
            name: Symbol name
            start: Start address
            stop: Stop address

        Returns:
            The matching kernel_symbol object if found, or None if no match is found.
        """

        num_elems = (stop - start) // self._kas_config.kernel_symbol_size

        return self._search_kernel_symbol_object_by_name(
            name,
            base=start,
            num_elems=num_elems,
        )

    def _cmp_kernel_symbol_name(
        self,
        name: str,
        kernel_symbol: interfaces.objects.ObjectInterface,
    ) -> int:
        return self._cmp_symbol_name(name, kernel_symbol.get_name())

    def _cmp_symbol_name(
        self,
        name: str,
        other: str,
    ) -> int:
        if name is None or other is None:
            return None
        elif name == other:
            return 0
        elif name < other:
            return -1
        else:
            return 1

    def _search_kernel_symbol_object_by_name(
        self, name: str, base: int, num_elems: int
    ) -> Optional[interfaces.objects.ObjectInterface]:
        """Search a kernel_symbol by name using binary search.

        Based on bsearch / __inline_bsearch()

        Args:
            name: Symbol name
            base: Base address
            num_elems: Number of elements

        Returns:
            A kernel_symbol object
        """
        vmlinux = self._context.modules[self._module_name]
        while num_elems > 0:
            pivot = base + (num_elems // 2) * self._kas_config.kernel_symbol_size

            kernel_symbol_pivot = vmlinux.object(
                object_type="kernel_symbol",
                offset=pivot,
                absolute=True,
            )

            result = self._cmp_kernel_symbol_name(name, kernel_symbol_pivot)
            if result == 0:
                return kernel_symbol_pivot
            elif result > 0:
                base = pivot + self._kas_config.kernel_symbol_size
                num_elems -= 1

            num_elems = num_elems // 2

        return None

    def get_modules_symbols(self, name: str = None) -> Iterator[KASSymbol]:
        """Yield each symbol from the kernel modules.
        This function iterates over the symbols of the kernel modules and yields them as
        KASSymbol objects.

        name (optional): If specified, the symbol name used to filter the symbols.

        Yields:
            KASSymbol objects
        """
        layer = self._context.layers[self._layer_name]
        for module in linux_utilities_modules.Modules.list_modules(
            self._context, self._module_name
        ):
            module_name = utility.array_to_string(module.name)
            for elf_sym_idx, elf_sym_obj in enumerate(module.get_symbols()):
                sym_name = elf_sym_obj.get_name()
                if not sym_name:
                    continue

                if name and name != sym_name:
                    continue

                # Normalize sym.st_value offset, which is an address pointing to the symbol value
                sym_address = elf_sym_obj.st_value & layer.address_mask
                sym_size = elf_sym_obj.st_size
                sym_type = module.get_symbol_type(elf_sym_obj, elf_sym_idx)
                is_exported = self._is_symbol_exported(sym_name, sym_address, module)
                sym_type = sym_type.upper() if is_exported else sym_type.lower()

                yield KASSymbol(
                    name=sym_name,
                    type=sym_type,
                    address=sym_address,
                    size=sym_size,
                    exported=is_exported,
                    module_name=module_name,
                    subsystem=self._MODULE_SUBSYSTEM_NAME,
                )

    def _ftrace_mod_get_symbols(self, address: int = None) -> Iterator[KASSymbol]:
        """Yield each symbol from the ftrace modules.
        This function iterates over the symbols of the ftrace modules and yields them as
        KASSymbol objects.

        Based on ftrace_mod_get_kallsym

        Args:
            address (optional): Address to filter symbols by

        Yields:
            KASSymbol objects
        """
        vmlinux = self._context.modules[self._module_name]
        layer = self._context.layers[self._layer_name]
        if not (
            vmlinux.has_type("ftrace_mod_map") and vmlinux.has_type("ftrace_mod_func")
        ):
            # kernel < 4.15 aba4b5c22cbac296f4081a0476d0c55828f135b4
            vollog.info(
                "Unsupported Ftrace kallsyms implementation. Ignore this if it's a kernel < 4.15"
            )
            return None

        symbol_table_name = vmlinux.symbol_table_name
        ftrace_mod_map_symname = f"{symbol_table_name}{constants.BANG}ftrace_mod_map"
        ftrace_mod_func_symname = f"{symbol_table_name}{constants.BANG}ftrace_mod_func"
        ftrace_mod_maps = vmlinux.object_from_symbol("ftrace_mod_maps")
        for mod_map in ftrace_mod_maps.to_list(ftrace_mod_map_symname, "list"):
            for mod_func in mod_map.funcs.to_list(ftrace_mod_func_symname, "list"):
                sym_name = utility.pointer_to_string(
                    mod_func.name, count=linux_constants.KSYM_NAME_LEN
                )
                sym_addr = mod_func.ip & layer.address_mask
                sym_size = mod_func.size
                if address is not None and not (
                    sym_addr <= address < sym_addr + sym_size
                ):
                    continue

                module_name = utility.array_to_string(mod_map.mod.name)
                kas_symbol = KASSymbol(
                    name=sym_name,
                    type=self._FTRACE_MODULE_SYM_TYPE,
                    address=sym_addr,
                    size=sym_size,
                    module_name=module_name,
                    subsystem=self._FTRACE_SUBSYSTEM_NAME,
                )
                kas_symbol.set_exported_from_type()
                yield kas_symbol

    def _ftrace_get_trampoline_symbols(
        self, address: int = None
    ) -> Iterator[KASSymbol]:
        """Yield each symbol from the ftrace trampoline.

        Based on ftrace_get_trampoline_kallsym

        Args:
            address (optional): Address to filter symbols by

        Yields:
            KASSymbol objects
        """
        # See kernel's ftrace_get_trampoline_kallsym()
        vmlinux = self._context.modules[self._module_name]
        if not vmlinux.has_type("ftrace_ops"):
            # kernels < 2.6.27 16444a8a40d4c7b4f6de34af0cae1f76a4f6c901
            return None

        if not vmlinux.has_symbol("ftrace_ops_trampoline_list"):
            # kernels < 5.9 fc0ea795f53c8d7040fa42471f74fe51d78d0834
            return None

        symbol_table_name = vmlinux.symbol_table_name
        ftrace_ops_symname = f"{symbol_table_name}{constants.BANG}ftrace_ops"
        ftrace_ops_trampoline_list = vmlinux.object_from_symbol(
            "ftrace_ops_trampoline_list"
        )

        for ftrace_op in ftrace_ops_trampoline_list.to_list(ftrace_ops_symname, "list"):
            sym_name = self._FTRACE_TRAMPOLINE_SYM
            sym_addr = ftrace_op.trampoline
            sym_size = ftrace_op.trampoline_size

            if address is not None and not (sym_addr <= address < sym_addr + sym_size):
                continue

            kas_symbol = KASSymbol(
                name=sym_name,
                type=self._FTRACE_TRAMPOLINE_SYM_TYPE,
                address=sym_addr,
                size=sym_size,
                module_name=self._FTRACE_TRAMPOLINE_MODULE_NAME,
                subsystem=self._FTRACE_SUBSYSTEM_NAME,
            )
            kas_symbol.set_exported_from_type()
            yield kas_symbol

    def get_ftrace_symbols(self) -> Iterator[KASSymbol]:
        """Yield each kernel ftrace symbol

        Yields:
            KASSymbol objects
        """
        yield from self._ftrace_mod_get_symbols()
        yield from self._ftrace_get_trampoline_symbols()

    def get_bpf_symbols(self) -> Iterator[KASSymbol]:
        """Yield each kernel BPF symbol

        Based on bpf_get_kallsym()

        Yields:
            KASSymbol objects
        """
        vmlinux = self._context.modules[self._module_name]
        if vmlinux.has_type("bpf_ksym"):
            # kernels >= 5.8
            list_type, list_head_member = "bpf_ksym", "lnode"
        elif vmlinux.has_type("bpf_prog_aux"):
            # 3.18 <= kernels < 5.8
            list_type, list_head_member = "bpf_prog_aux", "ksym_lnode"
        else:
            # kernels < 3.18
            vollog.info(
                "Unsupported BPF kallsysms implementation. Don't worry if kernel < 3.18"
            )
            return None

        symbol_table_name = vmlinux.symbol_table_name
        list_type_symname = f"{symbol_table_name}{constants.BANG}{list_type}"

        layer = self._context.layers[self._layer_name]

        # Even when bpf_jit_kallsyms is disabled (/proc/sys/net/core/bpf_jit_kallsyms = 0),
        # this function will still be able to gather the symbols.
        try:
            bpf_kallsyms_list = vmlinux.object_from_symbol("bpf_kallsyms")
        except exceptions.SymbolError:
            vollog.debug(
                "`bpf_kallsyms` symbol not present in the symbol table. Cannot proceed."
            )
            return None

        for elem in bpf_kallsyms_list.to_list(list_type_symname, list_head_member):
            try:
                # See kernel's bpf_get_kallsym()
                if list_type == "bpf_ksym":
                    # kernels >= 5.8
                    bpf_ksym = elem
                    sym_name = utility.array_to_string(bpf_ksym.name)
                    sym_addr = bpf_ksym.start
                    sym_size = bpf_ksym.end - bpf_ksym.start
                else:
                    # list_type == "bpf_prog_aux" 3.18 <= kernels < 5.8
                    bpf_prog_aux = elem
                    bpf_prog = bpf_prog_aux.prog
                    sym_name = bpf_prog.get_name()
                    sym_addr = bpf_prog.bpf_func
                    sym_start, sym_end = bpf_prog.get_address_region()
                    sym_size = sym_end - sym_start
            except exceptions.InvalidAddressException:
                continue

            # The following are also hardcoded in the Linux kernel
            # see kernel's get_ksymbol_bpf(), bpf_get_kallsym() and BPF_SYM_ELF_TYPE
            module_name = self._BPF_MODULE_NAME
            sym_type = self._BPF_SYM_TYPE
            sym_addr &= layer.address_mask

            kas_symbol = KASSymbol(
                name=sym_name,
                type=sym_type,
                address=sym_addr,
                size=sym_size,
                module_name=module_name,
                subsystem=self._BPF_SUBSYSTEM_NAME,
            )
            kas_symbol.set_exported_from_type()
            yield kas_symbol

    def get_all_symbols(self) -> Iterator[KASSymbol]:
        """Enumerates each kallsym symbol

        Yields:
            KASSymbol objects
        """
        yield from self.get_core_symbols()
        yield from self.get_modules_symbols()
        yield from self.get_ftrace_symbols()
        yield from self.get_bpf_symbols()

    def bpf_lookup_address(self, address: int) -> Optional[KASSymbol]:
        """Search for a BPF symbol based on its memory address.

        Based on bpf_address_lookup() and __bpf_address_lookup()

        Args:
            address: The memory address to search for

        Returns:
            The matching KASSymbol if found; otherwise, returns None
        """
        vmlinux = self._context.modules[self._module_name]

        if vmlinux.has_type("bpf_ksym"):
            # kernels >= 5.7 535911c80ad4f5801700e9d827a1985bbff41519
            bpf_ksym = self._find_bpf_ksym(address)
            if not bpf_ksym:
                return None
            symbol_start = bpf_ksym.start
            symbol_end = bpf_ksym.end
            sym_name = utility.array_to_string(bpf_ksym.name)
            sym_size = symbol_end - symbol_start
        elif vmlinux.has_type("latch_tree_root") and vmlinux.get_type(
            "bpf_prog_aux"
        ).has_member("ksym_tnode"):
            # For 4.11 <= kernels < 5.7
            # latch_tree_root was added in kernels 4.2 ade3f510f93a5613b672febe88eff8ea7f1c63b7
            # BPF kallsyms support was added in kernels 4.11 74451e66d516c55e309e8d89a4a1e7596e46aacd
            bpf_prog = self._find_bpf_prog(address)
            if not bpf_prog:
                return None

            symbol_start, symbol_end = bpf_prog.get_addr_region()
            sym_name = bpf_prog.get_name()
            sym_size = symbol_end - symbol_start
        else:
            # kernel < 4.11
            vollog.info(
                "Unsupported BPF kallsyms implementation. Ignore this if it's a kernel < 4.11"
            )
            return None

        layer = self._context.layers[self._layer_name]
        symbol_start &= layer.address_mask

        kas_symbol = KASSymbol(
            name=sym_name,
            type=self._BPF_SYM_TYPE,
            address=symbol_start,
            size=sym_size,
            module_name=self._BPF_MODULE_NAME,
            subsystem=self._BPF_SUBSYSTEM_NAME,
        )
        kas_symbol.set_exported_from_type()
        return kas_symbol

    def _find_bpf_prog(
        self, address: int
    ) -> Optional[interfaces.objects.ObjectInterface]:
        """Search for a BPF program based on its address.
        Based on __bpf_address_lookup & bpf_prog_kallsyms_find() for kernels < 5.7

        Args:
            address: The BPF symbol address to search for

        Returns:
            A bpf_prog object if found; otherwise, returns None.
        """
        vmlinux = self._context.modules[self._module_name]
        if not self._kas_config.bpf_tree_address:
            return None

        bpf_latch_tree_root = vmlinux.object(
            object_type="latch_tree_root",
            offset=self._kas_config.bpf_tree_address,
            absolute=True,
        )
        latch_tree_node = bpf_latch_tree_root.find(
            address, self._bpf_tree_comp_bpf_prog_aux
        )

        if not latch_tree_node:
            return None

        bpf_prog_aux = linux.LinuxUtilities.container_of(
            latch_tree_node.vol.offset, "bpf_prog_aux", "ksym_tnode", vmlinux
        )
        bpf_prog = bpf_prog_aux.prog
        return bpf_prog

    def _bpf_tree_comp_bpf_prog_aux(
        self, address: int, latch_tree_node: interfaces.objects.ObjectInterface
    ) -> int:
        """Comparison function used by _find_bpf_prog()
        Based on bpf_tree_comp for kernels < 5.7

        Args:
            address: The memory address to search for
            latch_tree_node: A latch tree node

        Returns:
            0: equal, >0: key is greater, <0: key is less than this bpf_prog
        """
        vmlinux = self._context.modules[self._module_name]
        layer = self._context.layers[self._layer_name]
        bpf_prog_aux = linux.LinuxUtilities.container_of(
            latch_tree_node.vol.offset, "bpf_prog_aux", "ksym_tnode", vmlinux
        )
        bpf_prog = bpf_prog_aux.prog
        bpf_start, bpf_end = bpf_prog.get_address_region()
        bpf_start &= layer.address_mask
        bpf_end &= layer.address_mask

        if address < bpf_start:
            return -1
        elif address > bpf_end:
            # Keep 'key > end' instead of 'key >= end'. This detects return addresses
            # within the program when the final instruction in a stack trace is a call.
            return 1
        else:
            return 0

    def _find_bpf_ksym(
        self, address: int
    ) -> Optional[interfaces.objects.ObjectInterface]:
        """Search for the respective bpf_ksym based on a symbol address.
        Based on __bpf_address_lookup & bpf_ksym_find() for kernels >= 5.7

        Args:
            address: The memory address to search for

        Returns:
            A bpf_ksym object if found; otherwise, returns None.
        """
        vmlinux = self._context.modules[self._module_name]
        if not self._kas_config.bpf_tree_address:
            return None

        bpf_latch_tree_root = vmlinux.object(
            object_type="latch_tree_root",
            offset=self._kas_config.bpf_tree_address,
            absolute=True,
        )
        latch_tree_node = bpf_latch_tree_root.find(
            address, self._bpf_tree_comp_bpf_ksym
        )
        if not latch_tree_node:
            return None

        bpf_ksym = linux.LinuxUtilities.container_of(
            latch_tree_node.vol.offset, "bpf_ksym", "tnode", vmlinux
        )
        return bpf_ksym

    def _bpf_tree_comp_bpf_ksym(
        self, address: int, latch_tree_node: interfaces.objects.ObjectInterface
    ) -> int:
        """Comparison function used by _find_bpf_ksym.

        Based on bpf_tree_comp in kernels >= 5.7

        Args:
            address: The memory address to search for
            latch_tree_node: A latch tree node

        Returns:
            0: equal, >0: key is greater, <0: key is less than this bpf_prog
        """
        #
        vmlinux = self._context.modules[self._module_name]
        layer = self._context.layers[self._layer_name]
        bpf_ksym = linux.LinuxUtilities.container_of(
            latch_tree_node.vol.offset, "bpf_ksym", "tnode", vmlinux
        )
        bpf_start = bpf_ksym.start & layer.address_mask
        bpf_end = bpf_ksym.end & layer.address_mask

        if address < bpf_start:
            return -1
        elif address > bpf_end:
            # Keep 'address > bpf_end' instead of 'address >= bpf_end'. This detects return
            # addresses within the program when the final instruction in a stack trace is a call.
            return 1
        else:
            return 0

    def ftrace_lookup_address(self, address: int) -> Optional[KASSymbol]:
        """Search for a ftrace symbol based on its address.

        Based on ftrace_mod_address_lookup()

        Args:
            address: The memory address to search for

        Returns:
            The matching KASSymbol if found, or None if no match is found.
        """

        # Filter by address and return only the first matching result.
        for kassymbol in self._ftrace_mod_get_symbols(address):
            return kassymbol

        for kassymbol in self._ftrace_get_trampoline_symbols(address):
            return kassymbol

        return None

    def _core_lookup_name_slow(self, name) -> Optional[KASSymbol]:
        """Search a core symbol by name

        Based on kallsyms_lookup_name in kernels < 6.2

        Args:
            name: The symbol name to search for.

        Returns:
            A KASSymbol object
        """
        # kernels < 6.2 60443c88f3a89fd303a9e8c0e84895910675c316
        current_offset = 0
        for sym_idx in range(self._kallsyms_num_syms):
            kassymbol, compressed_length = self._get_symbol(current_offset, sym_idx)
            if kassymbol and name == kassymbol.name:
                return kassymbol

            current_offset += compressed_length + 1

        return None

    @functools.cached_property
    def _kallsyms_seqs_of_names(self):
        vmlinux = self._context.modules[self._module_name]
        symbol_table_name = vmlinux.symbol_table_name
        unsigned_char_symname = symbol_table_name + constants.BANG + "unsigned char"
        # See 19bd8981dc2ee35fdc81ab1b0104b607c917d470: 3 bytes per index
        array_size = 3 * self._kallsyms_num_syms
        kallsyms_seqs_of_names = vmlinux.object(
            object_type="array",
            offset=self._kas_config.seqs_of_names_address,
            subtype=vmlinux.get_type(unsigned_char_symname),
            count=array_size,
            absolute=True,
        )
        return kallsyms_seqs_of_names

    def _get_symbol_seq(self, index: int) -> int:
        # See 19bd8981dc2ee35fdc81ab1b0104b607c917d470
        bits = 3
        seq = 0
        for i in range(bits):
            seq = (seq << 8) | self._kallsyms_seqs_of_names[bits * index + i]
        return seq

    def _get_symbol_by_index(self, index) -> Tuple[KASSymbolBasic, int]:
        seq = self._get_symbol_seq(index)
        offset = self._get_symbol_offset(seq)
        kassymbolbasic, _compressed_length = self._expand_symbol(offset)
        return kassymbolbasic

    def _lookup_name_index(self, name: str) -> Optional[int]:
        # based on kallsyms_lookup_names
        high = self._kallsyms_num_syms - 1
        low = 0

        while low <= high:
            mid = (low + high) // 2
            kassymbolbasic = self._get_symbol_by_index(mid)
            if not kassymbolbasic:
                return None

            ret = self._cmp_symbol_name(name, kassymbolbasic.name)
            if ret > 0:
                low = mid + 1
            elif ret < 0:
                high = mid - 1
            else:
                break

        if low > high:
            # Not found
            return None

        low = mid
        while low:
            kassymbolbasic = self._get_symbol_by_index(low - 1)
            if not kassymbolbasic:
                return None
            if self._cmp_symbol_name(name, kassymbolbasic.name) != 0:
                return low
            low -= 1

        return None

    def _core_lookup_name_fast(self, name: str) -> Optional[KASSymbol]:
        """Search a core symbol by name

        Based on kallsyms_lookup_name in kernels >= 6.2

        Args:
            name: The symbol name to search for

        Returns:
            A KASSymbol object
        """
        # kernels >= 6.2 60443c88f3a89fd303a9e8c0e84895910675c316
        index = self._lookup_name_index(name)
        if not index:
            return None

        seq = self._get_symbol_seq(index)
        offset = self._get_symbol_offset(seq)
        kassymbolbasic, _compressed_length = self._expand_symbol(offset)
        sym_address = self._get_symbol_address_by_index(seq)
        _seq, sym_size = self._get_symbol_pos(sym_address)

        kas_symbol = KASSymbol(
            name=kassymbolbasic.name,
            type=kassymbolbasic.type,
            address=sym_address,
            size=sym_size,
            module_name=self._CORE_MODULE_NAME,
            subsystem=self._CORE_SUBSYSTEM_NAME,
        )
        kas_symbol.set_exported_from_type()
        return kas_symbol

    def _kallsyms_lookup_name_modules(self, name: str) -> Optional[KASSymbol]:
        """_summary_

        Based on module_kallsyms_lookup_name

        Args:
            name: The symbol name to search for.

        Returns:
            A KASSymbol object
        """
        for kassymbol in self.get_modules_symbols(name):
            if name == kassymbol.name:
                # First match only
                return kassymbol
        return None

    def lookup_name(self, name: str) -> Optional[KASSymbol]:
        """Search symbols by name.
        WARNING: This function is super slow. The kernel does not index the symbols by
        name, so the it is a linear search.

        Based on kallsyms_lookup_name

        Args:
            name: The symbol name to search for.

        Returns:
            A KASSymbol object
        """
        if self._kas_config.seqs_of_names_address:
            # kernels >= 6.2:
            # 60443c88f3a89fd303a9e8c0e84895910675c316 and 19bd8981dc2ee35fdc81ab1b0104b607c917d470
            kassymbol = self._core_lookup_name_fast(name)
        else:
            # kernels < 6.2
            kassymbol = self._core_lookup_name_slow(name)

        if kassymbol:
            return kassymbol

        return self._kallsyms_lookup_name_modules(name)
