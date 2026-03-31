import logging
import warnings
import functools
import struct
from abc import ABCMeta, abstractmethod
from typing import (
    Callable,
    Dict,
    Generator,
    Iterable,
    Iterator,
    List,
    NamedTuple,
    Optional,
    Set,
    Tuple,
    Union,
)

from volatility3 import framework
from volatility3.framework import (
    constants,
    deprecation,
    exceptions,
    interfaces,
    objects,
    renderers,
    symbols,
)
from volatility3.framework.configuration import requirements
from volatility3.framework.objects import utility
from volatility3.framework.renderers import format_hints
from volatility3.framework.symbols.linux import extensions
from volatility3.framework.symbols.linux.utilities import tainting
from volatility3.framework.constants import linux as linux_constants

vollog = logging.getLogger(__name__)


class ModuleInfo(NamedTuple):
    """
    Used to track the name and boundary of a kernel module
    """

    offset: int
    name: str
    start: int
    end: int


class ModuleGathererInterface(
    interfaces.configuration.VersionableInterface, metaclass=ABCMeta
):
    _version = (1, 0, 0)
    _required_framework_version = (2, 0, 0)

    framework.require_interface_version(*_required_framework_version)

    gatherer_return_type = Generator[Union[ModuleInfo, "extensions.module"], None, None]

    # Must be set to a unique, descriptive name of the gathering technique or data structure source
    name = None

    @classmethod
    @abstractmethod
    def gather_modules(
        cls, context: interfaces.context.ContextInterface, kernel_module_name: str
    ) -> gatherer_return_type:
        """
        This method must return a generator (yield) of each `gatherer_return_type` found from its source
        """


class Modules(interfaces.configuration.VersionableInterface):
    """Kernel modules related utilities."""

    _version = (3, 0, 2)
    _required_framework_version = (2, 0, 0)

    framework.require_interface_version(*_required_framework_version)

    @classmethod
    def module_lookup_by_address(
        cls,
        context: interfaces.context.ContextInterface,
        kernel_module_name: str,
        modules: Iterable[ModuleInfo],
        target_address: int,
    ) -> Optional[Tuple[ModuleInfo, Optional[str]]]:
        """
        Determine if a target address lies in a module memory space.
        Returns the module where the provided address lies.

        `modules` must be non-empty and contain masked addresses via `get_module_info_for_module` or
        a ValueError will be thrown

        Args:
            context: The context on which to operate
            layer_name: The name of the layer on which to operate
            modules: An iterable containing the modules to match the address against
            target_address: The address to check for a match

        Returns:
            The first memory module in which the address fits and the symbol name for `target_address`

        Kernel documentation:
            "within_module" and "within_module_mem_type" functions
        """
        kernel = context.modules[kernel_module_name]

        kernel_layer = context.layers[kernel.layer_name]

        if not modules:
            raise ValueError("Empty list sent to `module_lookup_by_address`")

        matches = []
        for module in modules:
            if module.start != module.start & kernel_layer.address_mask:
                raise ValueError(
                    "Modules list must be gathered from `run_modules_scanners` to be used in this function"
                )

            if module.start <= target_address < module.end:
                matches.append(module)

        if len(matches) >= 1:
            if len(matches) > 1:
                warnings.warn(
                    f"Address {hex(target_address)} fits in modules at {[hex(module.start) for module in matches]}, indicating potential modules memory space overlap. The first matching entry {matches[0].name} will be used",
                    UserWarning,
                )

            symbol_name = None

            match = matches[0]

            if match.name == constants.linux.KERNEL_NAME:
                symbols = list(kernel.get_symbols_by_absolute_location(target_address))

                if len(symbols):
                    symbol_name = symbols[0]
            else:
                module = kernel.object("module", offset=module.offset, absolute=True)
                symbol_name = module.get_symbol_by_address(target_address)

            if symbol_name and symbol_name.find(constants.BANG) != -1:
                symbol_name = symbol_name.split(constants.BANG)[1]

            return match, symbol_name

        return None, None

    @classmethod
    @deprecation.method_being_removed(
        removal_date="2025-09-25",
        message="Code using this function should adapt `linux_utilities_modules.Modules.run_module_scanners`",
    )
    def mask_mods_list(
        cls,
        context: interfaces.context.ContextInterface,
        kernel_layer_name: str,
        mods: Iterator[extensions.module],
    ) -> List[Tuple[str, int, int]]:
        """
        A helper function to mask the starting and end address of kernel modules
        """
        mask = context.layers[kernel_layer_name].address_mask

        return [
            (
                utility.array_to_string(mod.name),
                mod.get_module_base() & mask,
                (mod.get_module_base() & mask) + mod.get_core_size(),
            )
            for mod in mods
        ]

    @classmethod
    @deprecation.method_being_removed(
        removal_date="2025-09-25",
        message="Use `module_lookup_by_address` to map address to their hosting kernel module and symbol.",
    )
    def lookup_module_address(
        cls,
        context: interfaces.context.ContextInterface,
        kernel_module_name: str,
        handlers: List[Tuple[str, int, int]],
        target_address: int,
    ) -> Tuple[str, str]:
        """
        Searches between the start and end address of the kernel module using target_address.
        Returns the module and symbol name of the address provided.
        """
        kernel_module = context.modules[kernel_module_name]
        mod_name = "UNKNOWN"
        symbol_name = "N/A"

        for name, start, end in handlers:
            if start <= target_address <= end:
                mod_name = name
                if name == constants.linux.KERNEL_NAME:
                    symbols = list(
                        kernel_module.get_symbols_by_absolute_location(target_address)
                    )

                    if len(symbols):
                        symbol_name = (
                            symbols[0].split(constants.BANG)[1]
                            if constants.BANG in symbols[0]
                            else symbols[0]
                        )

                break

        return mod_name, symbol_name

    @classmethod
    def get_module_info_for_module(
        cls, address_mask: int, module: extensions.module
    ) -> Optional[ModuleInfo]:
        """
        Returns a ModuleInfo instance for `module`

        This performs address masking to avoid endless calls to `mask_mods_list`

        Returns None if the name is smeared
        """
        try:
            mod_name = utility.array_to_string(module.name)
        except exceptions.InvalidAddressException:
            return None

        start = module.get_module_base() & address_mask

        end = start + module.get_core_size()

        return ModuleInfo(module.vol.offset, mod_name, start, end)

    @classmethod
    def run_modules_scanners(
        cls,
        context: interfaces.context.ContextInterface,
        kernel_module_name: str,
        caller_wanted_gatherers: List[ModuleGathererInterface],
        flatten: bool = True,
    ) -> Dict[str, List[ModuleInfo]]:
        """Run module scanning plugins and aggregate the results. It is designed
        to not operate any inter-plugin results triage.

        Rules for `caller_wanted_gatherers`:
            If `ModuleGatherers.all_gathers_identifier` is specified then every source will be populated

            If empty or an invalid gatherer is specified then a ValueError is thrown

            All gatherer names must be unique
        Args:
            called_wanted_sources: The list of sources to gather modules.
            flatten: Whether to de-duplicate modules across gatherers
        Returns:
            Dictionary mapping each gatherer to its corresponding result
        """
        if not caller_wanted_gatherers:
            raise ValueError(
                "`caller_wanted_gatherers` must have at least one gatherer."
            )

        if not isinstance(caller_wanted_gatherers, Iterable):
            raise ValueError("`caller_wanted_gatherers` must be iterable")

        seen_names = set()

        for gatherer in caller_wanted_gatherers:
            if not issubclass(gatherer, ModuleGathererInterface):
                raise ValueError(
                    f"Invalid gatherer sent through `caller_wanted_gatherers`: {gatherer}"
                )

            if not gatherer.name:
                raise ValueError(
                    f"{gatherer} does not have a valid name attribute, which is required. It must be a non-zero length string."
                )

            if gatherer.name in seen_names:
                raise ValueError(
                    f"{gatherer} has a name {gatherer.name} which has already been processed. Names must be unique."
                )

            seen_names.add(gatherer.name)

        kernel = context.modules[kernel_module_name]

        address_mask = context.layers[kernel.layer_name].address_mask

        run_results: Dict[ModuleGathererInterface, List[ModuleInfo]] = {}

        # Walk each source gathering modules
        for gatherer in caller_wanted_gatherers:
            run_results[gatherer.name] = []

            # process each module coming from back the current source
            for module in gatherer.gather_modules(context, kernel_module_name):
                # the kernel sends back a ModuleInfo directly
                if isinstance(module, ModuleInfo):
                    modinfo = module
                else:
                    modinfo = cls.get_module_info_for_module(address_mask, module)

                if modinfo:
                    run_results[gatherer.name].append(modinfo)

        if flatten:
            return cls.flatten_run_modules_results(run_results)

        return run_results

    @staticmethod
    @functools.lru_cache
    def get_modules_memory_boundaries(
        context: interfaces.context.ContextInterface,
        vmlinux_module_name: str,
    ) -> Tuple[int, int]:
        """Determine the boundaries of the module allocation area

        Args:
            context: The context to retrieve required elements (layers, symbol tables) from
            vmlinux_module_name: The name of the kernel module on which to operate

        Returns:
            A tuple containing the minimum and maximum addresses for the module allocation area.
        """
        vmlinux = context.modules[vmlinux_module_name]
        if vmlinux.has_symbol("mod_tree"):
            # Kernel >= 5.19    58d208de3e8d87dbe196caf0b57cc58c7a3836ca
            mod_tree = vmlinux.object_from_symbol("mod_tree")
            modules_addr_min = mod_tree.addr_min
            modules_addr_max = mod_tree.addr_max
        elif vmlinux.has_symbol("module_addr_min"):
            # 2.6.27 <= kernel < 5.19   3a642e99babe0617febb6f402e1e063479f489db
            modules_addr_min = vmlinux.object_from_symbol("module_addr_min")
            modules_addr_max = vmlinux.object_from_symbol("module_addr_max")

            if isinstance(modules_addr_min, objects.Void):
                raise exceptions.VolatilityException(
                    "Your ISF symbols lack type information. You may need to update the"
                    "ISF using the latest version of dwarf2json"
                )
        else:
            raise exceptions.VolatilityException(
                "Cannot find the module memory allocation area. Unsupported kernel"
            )

        return modules_addr_min, modules_addr_max

    @classmethod
    def flatten_run_modules_results(
        cls, run_results: Dict[str, List[ModuleInfo]], deduplicate: bool = True
    ) -> List[ModuleInfo]:
        """Flatten a dictionary mapping plugin names and modules list, to a single merged list.
        This is useful to get a generic lookup list of all the detected modules.

        Args:
            run_results: dictionary of plugin names mapping a list of detected modules
            deduplicate: remove duplicate modules, based on their offsets

        Returns:
            List of ModuleInfo objects
        """
        uniq_modules: List[ModuleInfo] = []

        seen_addresses: int = set()

        for modules in run_results.values():
            for module in modules:
                if deduplicate and (module.start in seen_addresses):
                    continue
                seen_addresses.add(module.start)
                uniq_modules.append(module)

        return uniq_modules

    @classmethod
    def get_hidden_modules(
        cls,
        context: interfaces.context.ContextInterface,
        vmlinux_module_name: str,
        known_module_addresses: Set[int],
        modules_memory_boundaries: Tuple,
    ) -> Iterable[extensions.module]:
        """Enumerate hidden modules by taking advantage of memory address alignment patterns

        This technique is much faster and uses less memory than the traditional scan method
        in Volatility2, but it doesn't work with older kernels.

        From kernels 4.2 struct module allocation are aligned to the L1 cache line size.
        In i386/amd64/arm64 this is typically 64 bytes. However, this can be changed in
        the Linux kernel configuration via CONFIG_X86_L1_CACHE_SHIFT. The alignment can
        also be obtained from the DWARF info i.e. DW_AT_alignment<64>, but dwarf2json
        doesn't support this feature yet.
        In kernels < 4.2, alignment attributes are absent in the struct module, meaning
        alignment cannot be guaranteed. Therefore, for older kernels, it's better to use
        the traditional scan technique.

        Args:
            context: The context to retrieve required elements (layers, symbol tables) from
            vmlinux_module_name: The name of the kernel module on which to operate
            known_module_addresses: Set with known module addresses
            modules_memory_boundaries: Minimum and maximum address boundaries for module allocation.
        Yields:
            module objects
        """
        vmlinux = context.modules[vmlinux_module_name]
        vmlinux_layer = context.layers[vmlinux.layer_name]

        module_addr_min, module_addr_max = modules_memory_boundaries
        module_address_alignment = cls.get_module_address_alignment(
            context, vmlinux_module_name
        )
        if not cls.validate_alignment_patterns(
            known_module_addresses, module_address_alignment
        ):
            vollog.warning(
                f"Module addresses aren't aligned to {module_address_alignment} bytes. "
                "Switching to 1 byte alignment scan method."
            )
            module_address_alignment = 1

        mkobj_offset = vmlinux.get_type("module").relative_child_offset("mkobj")
        mod_offset = vmlinux.get_type("module_kobject").relative_child_offset("mod")
        offset_to_mkobj_mod = mkobj_offset + mod_offset
        mod_member_template = vmlinux.get_type("module_kobject").child_template("mod")
        mod_size = mod_member_template.size
        mod_member_data_format = mod_member_template.data_format

        for module_addr in range(
            module_addr_min, module_addr_max, module_address_alignment
        ):
            if module_addr in known_module_addresses:
                continue

            try:
                # This is just a pre-filter. Module readability and consistency are verified in module.is_valid()
                self_referential_bytes = vmlinux_layer.read(
                    module_addr + offset_to_mkobj_mod, mod_size
                )
                self_referential = objects.convert_data_to_value(
                    self_referential_bytes, int, mod_member_data_format
                )
                if self_referential != module_addr:
                    continue
            except (
                exceptions.PagedInvalidAddressException,
                exceptions.InvalidAddressException,
            ):
                continue

            module = vmlinux.object("module", offset=module_addr, absolute=True)
            if module and module.is_valid():
                yield module

    @classmethod
    def get_module_address_alignment(
        cls,
        context: interfaces.context.ContextInterface,
        vmlinux_module_name: str,
    ) -> int:
        """Obtain the module memory address alignment.

        struct module is aligned to the L1 cache line, which is typically 64 bytes for most
        common i386/AMD64/ARM64 configurations. In some cases, it can be 128 bytes, but this
        will still work.

        Args:
            context: The context to retrieve required elements (layers, symbol tables) from
            vmlinux_module_name: The name of the kernel module on which to operate

        Returns:
            The struct module alignment
        """
        return context.modules[vmlinux_module_name].get_type("pointer").size

    @classmethod
    def list_modules(
        cls, context: interfaces.context.ContextInterface, vmlinux_module_name: str
    ) -> Iterable[interfaces.objects.ObjectInterface]:
        """Lists all the modules in the primary layer.

        Args:
            context: The context to retrieve required elements (layers, symbol tables) from
            layer_name: The name of the layer on which to operate
            vmlinux_symbols: The name of the table containing the kernel symbols

        Yields:
            The modules present in the `layer_name` layer's modules list

        This function will throw a SymbolError exception if kernel module support is not enabled.
        """
        vmlinux = context.modules[vmlinux_module_name]

        modules = vmlinux.object_from_symbol(symbol_name="modules").cast("list_head")

        table_name = vmlinux.symbol_table_name

        yield from modules.to_list(table_name + constants.BANG + "module", "list")

    @classmethod
    def get_kset_modules(
        cls, context: interfaces.context.ContextInterface, vmlinux_name: str
    ) -> Dict[str, extensions.module]:
        vmlinux = context.modules[vmlinux_name]

        try:
            module_kset = vmlinux.object_from_symbol("module_kset")
        except exceptions.SymbolError:
            module_kset = None

        if not module_kset:
            raise TypeError(
                "This plugin requires the module_kset structure. This structure is not present in the supplied symbol table. This means you are either analyzing an unsupported kernel version or that your symbol table is corrupt."
            )

        ret = {}

        kobj_off = vmlinux.get_type("module_kobject").relative_child_offset("kobj")

        for kobj in module_kset.list.to_list(
            vmlinux.symbol_table_name + constants.BANG + "kobject", "entry"
        ):
            mod_kobj = vmlinux.object(
                object_type="module_kobject",
                offset=kobj.vol.offset - kobj_off,
                absolute=True,
            )

            mod = mod_kobj.mod

            try:
                name = utility.pointer_to_string(kobj.name, 32)
            except exceptions.InvalidAddressException:
                continue

            if kobj.name and kobj.reference_count() > 2:
                ret[name] = mod

        return ret

    @staticmethod
    def validate_alignment_patterns(
        addresses: Iterable[int],
        address_alignment: int,
    ) -> bool:
        """Check if the memory addresses meet our alignments patterns

        Args:
            addresses: Iterable with the address values
            address_alignment: Number of bytes for alignment validation

        Returns:
            True if all the addresses meet the alignment
        """
        return all(addr % address_alignment == 0 for addr in addresses)

    @classmethod
    def _get_param_handlers(
        cls, context: interfaces.context.ContextInterface, vmlinux_name: str
    ) -> Tuple[Dict[int, str], Dict[str, Optional[int]]]:
        """
        This function builds the dictionaries needed to map kernel parameters to their types
        We need these values and information to properly decode each parameter to its input representation
        """
        kernel = context.modules[vmlinux_name]

        # All the integer type parameters
        pairs = {
            "param_get_invbool": "int",
            "param_get_bool": "int",
            "param_get_int": "int",
            "param_get_ulong": "long unsigned int",
            "param_get_ullong": "long long unsigned int",
            "param_get_long": "long int",
            "param_get_uint": "unsigned int",
            "param_get_ushort": "short unsigned int",
            "param_get_short": "short int",
            "param_get_byte": "char",
        }

        int_handlers: Dict[int, str] = {}

        for sym_name, val_type in pairs.items():
            try:
                sym_address = kernel.get_absolute_symbol_address(sym_name)
            except exceptions.SymbolError:
                continue

            int_handlers[sym_address] = val_type

        # Strings, arrays, booleans
        getters = {
            "param_get_string": None,
            "param_array_get": None,
            "param_get_charp": None,
            "param_get_bool": None,
            "param_get_invbool": None,
        }

        for sym_name in getters:
            try:
                sym_address = kernel.get_absolute_symbol_address(sym_name)
            except exceptions.SymbolError:
                continue

            getters[sym_name] = sym_address

        return int_handlers, getters

    @classmethod
    def _get_param_val(
        cls,
        context: interfaces.context.ContextInterface,
        vmlinux_name: str,
        int_handlers,
        getters,
        module,
        param,
    ) -> Optional[Union[str, int]]:
        """
        Properly determines the type of a parameter and decodes based on the type.
        The type is determined by examining its `get` function, which will be a pointer to
        predefined operations handler for particular parameter types.
        """

        # Attempt to retrieve the `get` pointer. Bail if smeared
        try:
            if hasattr(param, "get"):
                param_func = param.get
            else:
                param_func = param.ops.get

        except exceptions.InvalidAddressException:
            return None

        if not param_func:
            return None

        kernel = context.modules[vmlinux_name]

        # For arrays, recursively get the value of each member as the type can be different
        if param_func == getters["param_array_get"]:
            array = param.arr

            if array.num:
                max_index = array.num.dereference()
            else:
                max_index = array.member("max")

            if max_index > 32:
                vollog.debug(
                    f"Skipping array parameter with invalid index for module {module.vol.offset:#x}"
                )
                return None

            element_vals = []
            for i in range(max_index):
                kp = kernel.object(
                    object_type="kernel_param",
                    offset=array.elem + (array.elemsize * i),
                    absolute=True,
                )

                element_vals.append(
                    cls._get_param_val(
                        context, vmlinux_name, int_handlers, getters, module, kp
                    )
                )

            # nothing was gathered
            if not element_vals:
                return None

            return ",".join([str(ele) for ele in element_vals])

        # strings types
        elif param_func in [getters["param_get_string"], getters["param_get_charp"]]:
            try:
                if param_func == getters["param_get_string"]:
                    count = param.member("str").maxlen
                else:
                    count = 256

                return utility.pointer_to_string(param.member("str"), count=count)
            except exceptions.InvalidAddressException:
                vollog.debug(
                    f"Skipping string parameter with invalid address for module {module.vol.offset:#x}"
                )
                return None

        # The integer handles, which also encompass boolean handlers
        elif param_func in int_handlers:
            try:
                int_value = kernel.object(
                    object_type=int_handlers[param_func], offset=param.arg
                )
            except exceptions.InvalidAddressException:
                vollog.debug(
                    f"Skipping {int_handlers[param_func]} parameter with invalid address for module {module.vol.offset:#x}"
                )
                return None

            if param_func == getters["param_get_bool"]:
                if int_value == 0:
                    return "N"
                else:
                    return "Y"
            elif param_func == getters["param_get_invbool"]:
                if int_value == 0:
                    return "Y"
                else:
                    return "N"
            else:
                return int_value

        else:
            handler_symbol = kernel.get_symbols_by_absolute_location(param_func)

            msg = f"Unknown kernel parameter handling function ({handler_symbol}) at address {param_func:#x} for module at {module.vol.offset:#x}"

            # If a new kernel has a handler symbol we don't support then we want to always see that information
            # If the handler doesn't map to a kernel symbol then its smeared/invalid
            if handler_symbol:
                vollog.warning(msg)
            else:
                vollog.debug(msg)

            return None

    @classmethod
    def get_load_parameters(
        cls,
        context: interfaces.context.ContextInterface,
        vmlinux_name: str,
        module: extensions.module,
    ) -> Generator[Tuple[str, Optional[Union[str, int]]], None, None]:
        """
        Recovers the load parameters of the given kernel module
        Returns a tuple (key,value) for each parameter
        """
        if not hasattr(module, "kp"):
            vollog.debug(
                "kp member missing for struct module. Cannot recover parameters."
            )
            return None

        if module.num_kp > 128:
            vollog.debug(
                f"Smeared number of parameters ({module.num_kp}) found for module at offset {module.vol.offset:#x}"
            )
            return None

        kernel = context.modules[vmlinux_name]

        int_handlers, getters = cls._get_param_handlers(context, vmlinux_name)

        # Build the array of parameters
        param_array = kernel.object(
            object_type="array",
            offset=module.kp.dereference().vol.offset,
            subtype=kernel.get_type("kernel_param"),
            count=module.num_kp,
            absolute=True,
        )

        for i in range(len(param_array)):
            try:
                param = param_array[i]
                name = utility.pointer_to_string(param.name, count=32)
            except exceptions.InvalidAddressException:
                vollog.debug(
                    f"Smeared load parameter module at offset {module.vol.offset:#x}"
                )
                continue

            value = cls._get_param_val(
                context, vmlinux_name, int_handlers, getters, module, param
            )

            yield name, value


# This module is responsible for producing an ELF file of a kernel module (LKM) loaded in memory
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

    _version = (1, 0, 2)
    _required_framework_version = (2, 25, 0)

    framework.require_interface_version(*_required_framework_version)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.VersionRequirement(
                name="linux_utilities_modules_modules",
                component=Modules,
                version=(3, 0, 2),
            ),
        ]

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
        Args:
            context: The context on which to operate.
            vmlinux_name: The name of the kernel module.
            original_sections: Dict of module section addresses and names.
            section_sizes: Dict of module section addresses and sizes.
            sym_type_name: ELF symbol type name (should be one of "Elf64_Sym" or "Elf32_Sym").
            st_fmt: "struct"-like unpack format string (should be one of "<Q" or "<I").
            module: The Linux "module" object we're currently parsing.

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
        kernel = context.modules[vmlinux_name]
        kernel_layer = context.layers[kernel.layer_name]
        modules_addr_min, modules_addr_max = Modules.get_modules_memory_boundaries(
            context, vmlinux_name
        )
        modules_addr_min &= kernel_layer.address_mask
        modules_addr_max &= kernel_layer.address_mask
        original_sections = {}
        for index, section in enumerate(module.get_sections()):
            # Extra sanity check, to prevent OOM on heavily smeared samples at line
            # "size = next_address - address"
            if not (
                modules_addr_min
                <= section.address & kernel_layer.address_mask
                < modules_addr_max
            ):
                continue

            name = section.get_name()
            original_sections[section.address] = name

        if not original_sections:
            return None

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
                    f"Could not construct a symbol table for module at {module.vol.offset}. Cannot recover."
                )
                return None

            symtab_index = len(updated_sections)

            # Manually add symtab with the correct data
            updated_sections.append((".symtab", symtab_address, file_offset, data))

        else:
            vollog.debug(
                f"Did not find a .symtab section for module at {module.vol.offset:#x}. Cannot recover."
            )
            return None

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

        e_type = struct.pack("<H", 1)  # relocatable
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
        parse_sections_result = cls._parse_sections(context, vmlinux_name, module)
        if parse_sections_result is None:
            return None
        updated_sections, strtab_index, symtab_index = parse_sections_result

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

            # concatenate the header and section bytes
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


class ModuleGathererLsmod(ModuleGathererInterface):
    """
    Gathers modules from the main kernel list
    """

    _version = (1, 0, 0)

    name = "Lsmod"

    @classmethod
    def gather_modules(
        cls, context: interfaces.context.ContextInterface, kernel_module_name: str
    ) -> ModuleGathererInterface.gatherer_return_type:
        yield from Modules.list_modules(context, kernel_module_name)


class ModuleGathererSysFs(ModuleGathererInterface):
    """
    Gathers modules from the sysfs /sys/modules objects
    """

    _version = (1, 0, 0)

    name = "SysFs"

    @classmethod
    def gather_modules(
        cls, context: interfaces.context.ContextInterface, kernel_module_name: str
    ) -> ModuleGathererInterface.gatherer_return_type:
        kernel = context.modules[kernel_module_name]

        sysfs_modules: dict = Modules.get_kset_modules(context, kernel_module_name)

        for m_offset in sysfs_modules.values():
            yield kernel.object(object_type="module", offset=m_offset, absolute=True)


class ModuleGathererScanner(ModuleGathererInterface):
    """
    Gathers modules by scanning memory
    """

    _version = (1, 0, 0)

    name = "Scanner"

    @classmethod
    def gather_modules(
        cls, context: interfaces.context.ContextInterface, kernel_module_name: str
    ) -> ModuleGathererInterface.gatherer_return_type:
        modules_memory_boundaries = Modules.get_modules_memory_boundaries(
            context, kernel_module_name
        )

        # Send in an empty list to not filter on any modules
        yield from Modules.get_hidden_modules(
            context=context,
            vmlinux_module_name=kernel_module_name,
            known_module_addresses=[],
            modules_memory_boundaries=modules_memory_boundaries,
        )


class ModuleGathererKernel(ModuleGathererInterface):
    """
    Creates a ModuleInfo instance for the kernel so that plugins
    can determine when function pointers reference the kernel
    """

    _version = (1, 0, 0)

    name = "kernel"

    @classmethod
    def gather_modules(
        cls, context: interfaces.context.ContextInterface, kernel_module_name: str
    ) -> ModuleGathererInterface.gatherer_return_type:
        """
        Returns a ModuleInfo instance that encodes the kernel
        This is required to map function pointers to the kernel executable
        """
        kernel = context.modules[kernel_module_name]

        address_mask = context.layers[kernel.layer_name].address_mask

        start_addr = kernel.object_from_symbol("_text")
        start_addr = start_addr.vol.offset & address_mask

        end_addr = kernel.object_from_symbol("_etext")
        end_addr = end_addr.vol.offset & address_mask

        yield ModuleInfo(start_addr, constants.linux.KERNEL_NAME, start_addr, end_addr)


class ModuleGatherers(
    interfaces.configuration.VersionableInterface,
    interfaces.configuration.ConfigurableInterface,
):
    _version = (1, 0, 0)
    _required_framework_version = (2, 0, 0)

    framework.require_interface_version(*_required_framework_version)

    # Valid sources of cores kernel module gatherers to send to `run_module_scanners`
    # With few exceptions, rootkit checking plugins want all sources
    # This provides a stable identifier as new sources are added over time
    all_gatherers_identifier = [
        ModuleGathererLsmod,
        ModuleGathererSysFs,
        ModuleGathererScanner,
        ModuleGathererKernel,
    ]

    @classmethod
    def get_requirements(cls):
        reqs = []

        # for now, all versions are 1, this will be broken out if/when that changes
        for gatherer in ModuleGatherers.all_gatherers_identifier:
            reqs.append(
                requirements.VersionRequirement(
                    name=gatherer.name.replace(" ", ""),
                    component=gatherer,
                    version=(1, 0, 0),
                )
            )

        return reqs


class ModuleDisplayPlugin(interfaces.configuration.VersionableInterface):
    """
    Plugins that enumerate kernel modules (lsmod, check_modules, etc.)
    must inherit from this class to have unified output columns across plugins.
    The constructor of the plugin must call super() with the `implementation` set
    """

    _version = (2, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.VersionRequirement(
                name="linux_utilities_modules",
                component=Modules,
                version=(3, 0, 1),
            ),
            requirements.VersionRequirement(
                name="linux-tainting", component=tainting.Tainting, version=(1, 0, 0)
            ),
        ]

    @classmethod
    def generate_results(
        cls,
        context: interfaces.context.ContextInterface,
        implementation: Callable[
            [interfaces.context.ContextInterface, str], Iterable[extensions.module]
        ],
        kernel_module_name: str,
        dump: bool,
        open_implementation: Optional[interfaces.plugins.FileHandlerInterface],
    ):
        """
        Uses the implementation set in the constructor call to produce consistent output fields
        across module gathering plugins
        """
        for module in implementation(context, kernel_module_name):
            try:
                name = utility.array_to_string(module.name)
            except exceptions.InvalidAddressException:
                vollog.debug(
                    f"Unable to recover name for module {module.vol.offset:#x} from implementation {implementation}"
                )
                continue

            code_size = format_hints.Hex(
                module.get_init_size() + module.get_core_size()
            )

            taints = ",".join(
                tainting.Tainting.get_taints_parsed(
                    context, kernel_module_name, module.taints, True
                )
            )

            parameters_iter = Modules.get_load_parameters(
                context, kernel_module_name, module
            )

            parameters = ", ".join([f"{key}={value}" for key, value in parameters_iter])

            file_name = renderers.NotApplicableValue()

            if dump and open_implementation:
                elf_data = ModuleExtract.extract_module(
                    context, kernel_module_name, module
                )
                if not elf_data:
                    vollog.warning(
                        f"Unable to reconstruct the ELF for module struct at {module.vol.offset:#x}"
                    )
                    file_name = renderers.NotAvailableValue()
                else:
                    file_name = open_implementation.sanitize_filename(
                        f"kernel_module.{name}.{module.vol.offset:#x}.elf"
                    )

                    with open_implementation(file_name) as file_handle:
                        file_handle.write(elf_data)

            yield (
                0,
                (
                    format_hints.Hex(module.vol.offset),
                    name,
                    format_hints.Hex(code_size),
                    taints,
                    parameters,
                    file_name,
                ),
            )

    columns_results = [
        ("Offset", format_hints.Hex),
        ("Module Name", str),
        ("Code Size", format_hints.Hex),
        ("Taints", str),
        ("Load Arguments", str),
        ("File Output", str),
    ]
