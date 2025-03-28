import logging
import warnings
from typing import (
    Iterable,
    Iterator,
    List,
    Optional,
    Tuple,
    NamedTuple,
    Dict,
    Set,
    Generator,
    Union,
)
from abc import ABCMeta, abstractmethod

from volatility3 import framework
from volatility3.framework import (
    constants,
    interfaces,
    deprecation,
    exceptions,
    objects,
    renderers,
)
from volatility3.framework.constants import architectures
from volatility3.framework.renderers import format_hints
from volatility3.framework.configuration import requirements
from volatility3.framework.objects import utility
from volatility3.framework.symbols.linux import extensions
from volatility3.framework.symbols.linux.utilities import tainting

import volatility3.framework.symbols.linux.utilities.module_extract as linux_utilities_module_extract

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

    _version = (3, 0, 1)
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
    ) -> Iterable[interfaces.objects.ObjectInterface]:
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
                "Switching to 1 byte aligment scan method."
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
        # FIXME: When dwarf2json/ISF supports type alignments. Read it directly from the type metadata
        # Additionally, while 'context' and 'vmlinux_module_name' are currently unused, they will be
        # essential for retrieving type metadata in the future.
        return 64

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

        # For arrays, recusively get the value of each member as the type can be different
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
        This is required to map function pointers to the kerenl executable
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

    _version = (1, 0, 1)
    _required_framework_version = (2, 0, 0)

    framework.require_interface_version(*_required_framework_version)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Linux kernel",
                architectures=architectures.LINUX_ARCHS,
            ),
            requirements.VersionRequirement(
                name="linux_utilities_modules",
                component=Modules,
                version=(3, 0, 1),
            ),
            requirements.VersionRequirement(
                name="linux-tainting", component=tainting.Tainting, version=(1, 0, 0)
            ),
            requirements.BooleanRequirement(
                name="dump",
                description="Extract listed modules",
                default=False,
                optional=True,
            ),
        ]

    def generator(self):
        """
        Uses the implementation set in the constructor call to produce consistent output fields
        across module gathering plugins
        """
        for module in self.implementation(self.context, self.config["kernel"]):
            try:
                name = utility.array_to_string(module.name)
            except exceptions.InvalidAddressException:
                vollog.debug(
                    f"Unable to recover name for module {module.vol.offset:#x} from implementation {self.implementation}"
                )
                continue

            code_size = format_hints.Hex(
                module.get_init_size() + module.get_core_size()
            )

            taints = ",".join(
                tainting.Tainting.get_taints_parsed(
                    self.context, self.config["kernel"], module.taints, True
                )
            )

            parameters_iter = Modules.get_load_parameters(
                self.context, self.config["kernel"], module
            )

            parameters = ", ".join([f"{key}={value}" for key, value in parameters_iter])

            file_name = renderers.NotApplicableValue()

            if self.config["dump"]:
                elf_data = linux_utilities_module_extract.ModuleExtract.extract_module(
                    self.context, self.config["kernel"], module
                )
                if not elf_data:
                    vollog.warning(
                        f"Unable to reconstruct the ELF for module struct at {module.vol.offset:#x}"
                    )
                    file_name = renderers.NotAvailableValue()
                else:
                    file_name = self.open.sanitize_filename(
                        f"kernel_module.{name}.{module.vol.offset:#x}.elf"
                    )

                    with self.open(file_name) as file_handle:
                        file_handle.write(elf_data)

            yield 0, (
                format_hints.Hex(module.vol.offset),
                name,
                format_hints.Hex(code_size),
                taints,
                parameters,
                file_name,
            )

    def run(self):
        return renderers.TreeGrid(
            [
                ("Offset", format_hints.Hex),
                ("Module Name", str),
                ("Code Size", format_hints.Hex),
                ("Taints", str),
                ("Load Arguments", str),
                ("File Output", str),
            ],
            self._generator(),
        )
