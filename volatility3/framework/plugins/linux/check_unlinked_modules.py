# This file is Copyright 2023 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
import logging
from typing import List, Dict
from volatility3.plugins.linux import check_modules
from volatility3.framework import interfaces, exceptions
from volatility3.framework.configuration import requirements
from volatility3.framework.renderers import format_hints, TreeGrid
from volatility3.framework.symbols import linux
from volatility3.framework.objects import (
    utility,
    PrimitiveObject,
    Boolean,
    Enumeration,
    templates,
)
from enum import Enum
from volatility3.framework.layers import scanners

vollog = logging.getLogger(__name__)
MAX_KERNEL_MEMORY_SEARCH_LIMIT = 2**20  # Arbitrary constant


class Check_unlinked_modules(interfaces.plugins.PluginInterface):
    """Scan memory for unlinked modules"""

    _version = (1, 0, 1)
    _required_framework_version = (2, 5, 2)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Linux kernel",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.PluginRequirement(
                name="check_modules",
                plugin=check_modules.Check_modules,
                version=(0, 0, 0),
            ),
            requirements.IntRequirement(
                name="leaked_address",
                description="Optimized memory scan, around a leaked address from an hidden module (e.g. ftrace callback)",
                optional=True,
                default=0,
            ),
        ]

    @classmethod
    def wrapper_get_sysfs_modules(
        cls,
        context: interfaces.context.ContextInterface,
        config_path: str,
        vmlinux_name: str,
    ):
        """Wrapper for check_modules plugin, return a list of modules (similarly to the lsmod plugin)"""

        vmlinux = context.modules[vmlinux_name]
        sysfs_modules: dict = check_modules.Check_modules(
            context, config_path
        ).get_kset_modules(context, vmlinux_name)
        # Convert get_kset_modules() offsets back to module objects
        for m_offset in sysfs_modules.values():
            yield vmlinux.object(object_type="module", offset=m_offset, absolute=True)

    @classmethod
    def lookup_sysfs_hidden_modules(
        cls,
        context: interfaces.context.ContextInterface,
        vmlinux_name: str,
        modules_handlers: list,
        leaked_address: int = 0,
    ):
        """
        Some rootkits unlink themselves from list_head AND module_kobject. However, due to the use of a callback (e.g. via ftrace), they reveal an address inside their module memory.
        Doing so, we can scan the close memory range of the callback for any "module" structs.
        Most of the time, a hidden rootkit memory range will be located between two other modules, giving us some minimum and maximum range to search in.
        Note : callbacks with values like 0xffffffffffffffff will fail with DEBUG : "Scan Failure: Sections have no size, nothing to scan". This ensure that pottential OOB reads won't crash the plugin.

        Current framework implementation does not take into account modules with non-printable characters in their name.
        To avoid changing too much of the framework, we'll follow the same path.
        However, a module might have a name like "\xde\xad\xbe\xef", which would need manual investigation with volshell to uncover.
        In the case of multiple modules on a same memory dump nulling their name (e.g. rootkit "osom"), it could result in multiple modules with empty names, overlapping in the handers list.
        """

        vmlinux = context.modules[vmlinux_name]
        flattened_handlers = flatten_modules_handlers(modules_handlers)
        flattened_handlers.sort()
        if leaked_address != 0:
            (
                low_address,
                high_address,
            ) = calculate_closest_modules_from_address(
                target_address=leaked_address,
                flattened_handlers=flattened_handlers,
            )
            if low_address == None:
                low_address = leaked_address - MAX_KERNEL_MEMORY_SEARCH_LIMIT
            if high_address == None:
                high_address = leaked_address + MAX_KERNEL_MEMORY_SEARCH_LIMIT

            # Search : between previous module and leaked address ; between leaked address and next module
            sections_to_scan = [
                (low_address, leaked_address - low_address),
                (leaked_address, high_address - leaked_address),
            ]
            vollog.info(
                f"Searching modules structs from {hex(low_address)} to {hex(high_address)}, based on provided address {hex(leaked_address)}..."
            )
        else:
            low_address = flattened_handlers[0] - MAX_KERNEL_MEMORY_SEARCH_LIMIT
            high_address = flattened_handlers[-1] + MAX_KERNEL_MEMORY_SEARCH_LIMIT
            # Search : between first and last modules ; before first module ; after last module
            sections_to_scan = [
                (flattened_handlers[0], flattened_handlers[-1] - flattened_handlers[0]),
                (low_address, flattened_handlers[0] - low_address),
                (flattened_handlers[-1], high_address - flattened_handlers[-1]),
            ]
            vollog.info(
                f"Searching modules structs, in (start, size) : {[(hex(x[0]), x[1]) for x in sections_to_scan]}..."
            )
        scanned_modules = scan_memory_for_modules(
            context=context,
            kernel_module_name=vmlinux.name,
            sections_to_scan=sections_to_scan,
        )

        return_modules = []
        for scanned_module in list(scanned_modules):
            scanned_module_handler = linux.LinuxUtilities.generate_kernel_handler_info(
                context, vmlinux.name, (scanned_module,)
            )[
                1
            ]  # Skip __kernel__

            # Check if scanned module already exists in our lists
            if not any(
                scanned_module_handler == existing_handler
                for existing_handler in modules_handlers
            ):
                return_modules.append(scanned_module)
                vollog.info(
                    f'Found sysfs non-listed module "{utility.array_to_string(scanned_module.name)}" at {hex(scanned_module.vol.offset)}'
                )

        return return_modules

    def _generator(
        self, sysfs_handlers: list, sysfs_modules: list, leaked_address: int = 0
    ):
        vmlinux = self.context.modules[self.config["kernel"]]

        # Detect unlinked modules
        sysfs_unlinked_modules = self.lookup_sysfs_hidden_modules(
            self.context,
            vmlinux.name,
            sysfs_handlers,
            leaked_address,
        )

        dict_sysfs_modules = dict(
            (str(utility.array_to_string(module.name)), module)
            for module in sysfs_modules
        )
        dict_sysfs_unlinked_modules = dict(
            (str(utility.array_to_string(module.name)), module)
            for module in sysfs_unlinked_modules
        )
        for mod in set(dict_sysfs_unlinked_modules.items()).difference(
            set(dict_sysfs_modules.items())
        ):
            yield mod

    def run(self):
        vmlinux = self.context.modules[self.config["kernel"]]

        # Get /sys/module/ listed modules
        sysfs_modules = list(
            self.wrapper_get_sysfs_modules(self.context, self.config_path, vmlinux.name)
        )
        # Calculate boundaries for each module
        sysfs_handlers = linux.LinuxUtilities.generate_kernel_handler_info(
            self.context, vmlinux.name, sysfs_modules
        )[
            1:
        ]  # Skip __kernel__, else the range to search in will be huge (_stext to _etext)

        detected_modules = self._generator(
            sysfs_handlers=sysfs_handlers,
            sysfs_modules=sysfs_modules,
            leaked_address=self.config.get("leaked_address"),
        )
        return TreeGrid(
            [("Module Address", format_hints.Hex), ("Module Name", str)],
            [
                (0, (format_hints.Hex(mod[1].vol.offset), mod[0]))
                for mod in detected_modules
            ],
        )


## UTILITIES ##
def regex_from_struct_members(
    context: interfaces.context.ContextInterface,
    kernel_module_name: str,
    vol_struct: templates.ObjectTemplate,
    path: List = [],
    overrides: Dict[str, bytes] = {},
    stop_key: str = "",
):
    """Walk an ObjectTemplate members to create a matching RegEx.
    This is useful to search for a struct artifacts in memory, while taking into account variants from one symbol table to another (one kernel to another).
    """
    kernel = context.modules[kernel_module_name]

    # Sort struct members and flatten dict
    struct_members = dict(
        sorted(vol_struct.vol.members.items(), key=lambda item: item[1][0])
    )
    struct_members_list = []
    for name, (offset, obj) in struct_members.items():
        struct_members_list.append((name, offset, obj))
        if name == stop_key and path == []:
            break
    struct_size = vol_struct.size
    struct_regex = []
    consumed = 0

    # Iterate over every member of the struct
    for i, member in enumerate(struct_members_list):
        name, offset, obj = member
        object_class: PrimitiveObject | None = obj.vol.get("object_class")
        if i < len(struct_members_list) - 1:
            member_len = struct_members_list[i + 1][1] - offset
        else:
            member_len = struct_size - offset
        consumed += member_len
        # Keep track of the depth and path of this element, starting from the root object
        path.append(name)
        # Determine what regex to use, depending on the element type
        if ".".join(path) in overrides:
            round_regex = overrides[".".join(path)]
        elif object_class == Enumeration:
            choices = []
            for choice in obj.vol.choices.values():
                choices.append(int.to_bytes(choice, member_len, "little", signed=True))
            round_regex = b"(?:" + b"|".join(choices) + b")"
        elif object_class == Boolean:
            possible_values = []
            for byte_order in ["little", "big"]:
                for possible_value in [0, 1]:
                    possible_values.append(
                        int.to_bytes(possible_value, member_len, byte_order)
                    )
                # don't bother with endianness on 1 byte
                if member_len == 1:
                    break

            round_regex = b"(?:" + b"|".join(possible_values) + b")"

            # # Possible alignement problem when not using lookbehind here
            # if member_len > 1:
            #     round_regex = b"(?=" + round_regex + b")"
        else:
            type_name = obj.vol.type_name
            # Recursive introspection, call this function again to analyze a sub-element
            if kernel.has_type(type_name) and kernel.get_type(type_name).vol.get(
                "members"
            ):
                type = kernel.get_type(type_name)
                tmp_regex, ret_consumed = regex_from_struct_members(
                    context, kernel_module_name, type, path, overrides
                )
                # Detect missing bytes (padding)
                if member_len > ret_consumed:
                    padding = member_len - ret_consumed
                    tmp_regex += f".{{{padding}}}".encode()
                round_regex = tmp_regex
            # We can't make assumptions about this element
            else:
                round_regex = f".{{{member_len}}}".encode()

        # vollog.debug(f"path : {path} : {round_regex}")
        struct_regex.append(round_regex)
        # We are done with this element
        path.remove(name)

    # Use a lookahead to allow overlapping matches (only around final struct_regex)
    if len(path) == 0:
        return (
            b"(?=" + b"".join(struct_regex) + b")",
            consumed,
        )
    else:
        return b"".join(struct_regex), consumed


class RegexOverrides(Enum):
    """Custom overrides"""

    # Match anything but \x00{ptr_size}
    NON_NULL_POINTER = (
        lambda ptr_size: b"(?:(?!\x00" + f"{{{ptr_size}}}).{{{ptr_size}}})".encode()
    )


def scan_memory_for_modules(
    context: interfaces.context.ContextInterface,
    kernel_module_name: str,
    sections_to_scan: list,
):
    """Scan a memory region to uncover modules structs

    Args:
            context: The current context
            kernel_module_name: The name of the kernel module
            sections_to_scan: A list of tuples including a start address and a size
    Yields:
            A module object
    """
    kernel = context.modules[kernel_module_name]
    m_struct = kernel.get_symbol("module").type.vol.subtype
    ptr_size = kernel.get_type("pointer").size

    # We assume module.mkobj.mod is a non-null pointer to the module itself, allowing us to drastically reduce regex candidates
    overrides = {
        "mkobj.mod": RegexOverrides.NON_NULL_POINTER(ptr_size),
        "init_layout.mnt.mod": RegexOverrides.NON_NULL_POINTER(ptr_size),
    }

    # Using a regex too long will eventually result in overlapping and alignements problems, so stop at mkobj
    stop_key = "mkobj"
    module_regex, s = regex_from_struct_members(
        context, kernel_module_name, m_struct, overrides=overrides, stop_key=stop_key
    )
    scanner = scanners.RegExScanner(module_regex)
    scanned = context.layers[kernel.layer_name].scan(
        context=context, scanner=scanner, sections=sections_to_scan
    )
    # Iterate over candidates structs
    for module_candidate_offset in scanned:
        # Use a try-except block to avoid crashing on OOB read
        try:
            m = kernel.object(
                object_type="module", offset=module_candidate_offset, absolute=True
            )
            # Check if module mkobj.mod points to the candidate offset
            if m.mkobj.mod == module_candidate_offset:
                vollog.info(
                    f'Found module "{utility.array_to_string(m.name)}" at {hex(m.vol.offset)}'
                )
                yield m
        except exceptions.InvalidAddressException:
            continue


def calculate_closest_modules_from_address(
    target_address: int, flattened_handlers: list
):
    """Determine closest modules for a given address.

    Args:
            target_address: The target address to search boundaries for
            handlers_set: A list containing an unordered list with flattened (module_start, module_end) from handlers. See flatten_modules_handlers() for reference.
    Returns:
            Tuple containing previous and next boundary
    """
    # Insert target_address and sort
    flattened_handlers.append(target_address)
    flattened_handlers.sort()
    # Determine position of target_address in list
    target_address_index = flattened_handlers.index(target_address)
    # Check if target_address index in list is : top of the list > bottom of the list > any other case
    if target_address_index + 1 >= len(flattened_handlers):
        return (
            flattened_handlers[target_address_index - 1],
            None,
        )  # No next boundary
    elif target_address_index - 1 < 0:
        return (
            None,
            flattened_handlers[target_address_index + 1],
        )  # No previous boundary
    else:
        return (
            flattened_handlers[target_address_index - 1],
            flattened_handlers[target_address_index + 1],
        )


def flatten_modules_handlers(
    handlers: list,
):
    """Flatten a list of previously calculated modules handlers boundaries (extract all "start" and "end")"""
    return list(
        sum(
            [(h[2], h[3]) for h in set(handlers)],
            (),
        )
    )
