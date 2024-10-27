# This file is Copyright 2023 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
import logging
from typing import List, Optional
from enum import Enum
from volatility3.plugins.linux import lsmod, check_unlinked_modules
from volatility3.framework import constants, exceptions, interfaces
from volatility3.framework.configuration import requirements
from volatility3.framework.renderers import format_hints, TreeGrid
from volatility3.framework.symbols import linux
from volatility3.framework.objects import utility

vollog = logging.getLogger(__name__)
UNKNOWN = "UNKNOWN"


class FTRACEFLAGS(Enum):
    FTRACE_OPS_FL_ENABLED = 1 << 0
    FTRACE_OPS_FL_DYNAMIC = 1 << 1
    FTRACE_OPS_FL_SAVE_REGS = 1 << 2
    FTRACE_OPS_FL_SAVE_REGS_IF_SUPPORTED = 1 << 3
    FTRACE_OPS_FL_RECURSION = 1 << 4
    FTRACE_OPS_FL_STUB = 1 << 5
    FTRACE_OPS_FL_INITIALIZED = 1 << 6
    FTRACE_OPS_FL_DELETED = 1 << 7
    FTRACE_OPS_FL_ADDING = 1 << 8
    FTRACE_OPS_FL_REMOVING = 1 << 9
    FTRACE_OPS_FL_MODIFYING = 1 << 10
    FTRACE_OPS_FL_ALLOC_TRAMP = 1 << 11
    FTRACE_OPS_FL_IPMODIFY = 1 << 12
    FTRACE_OPS_FL_PID = 1 << 13
    FTRACE_OPS_FL_RCU = 1 << 14
    FTRACE_OPS_FL_TRACE_ARRAY = 1 << 15
    FTRACE_OPS_FL_PERMANENT = 1 << 16
    FTRACE_OPS_FL_DIRECT = 1 << 17


class Check_ftrace(interfaces.plugins.PluginInterface):
    """Detect ftrace hooking"""

    _version = (1, 0, 0)
    _required_framework_version = (2, 5, 2)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Linux kernel",
                architectures=["Intel32", "Intel64", "AArch64"],
            ),
            requirements.PluginRequirement(
                name="lsmod", plugin=lsmod.Lsmod, version=(2, 0, 0)
            ),
            requirements.PluginRequirement(
                name="check_unlinked_modules",
                plugin=check_unlinked_modules.Check_unlinked_modules,
                version=(1, 0, 0),
            ),
            requirements.BooleanRequirement(
                name="show_ftrace_flags",
                description="Show ftrace flags associated with an ftrace_ops",
                optional=True,
                default=False,
            ),
        ]

    def run(self):
        """Plugin output format :

        ftrace_ops : hex("ftrace_ops struct offset")
        Callback : "callback offset" ["callback symbol" | "UNKNOWN"]
        Hooked symbol : "hooked symbol" | "UNKNOWN"
        Module :  hex("module offset") ["associated module"] | "UNKNOWN"
        Callback out of kernel .text : True | False
        ftrace flags : list("ftrace_ops flags")
        """

        # Naturally ordered by "ftrace_ops" (the same order as we walked the "ftrace_ops_list")
        columns = [
            ("ftrace_ops", format_hints.Hex),
            ("Callback", str),
            ("Hooked symbol", str),
            ("Module", str),
            ("Callback out of kernel .text", bool),
        ]

        if self.config.get("show_ftrace_flags"):
            columns.append(("ftrace_ops flags", str))

        return TreeGrid(
            columns,
            self._generator(),
        )

    def _generator(self):
        """Iterate over ftrace_ops_list struct"""

        self.vmlinux = self.context.modules[self.config["kernel"]]
        if not self.vmlinux.has_symbol("ftrace_ops_list"):
            raise exceptions.SymbolError(
                "ftrace_ops_list",
                self.vmlinux.symbol_table_name,
                'The provided symbol table does not include the "ftrace_ops_list" symbol. This means you are either analyzing an unsupported kernel version or that your symbol table is corrupt.',
            )

        self.checked_callbacks = {}
        self.set_compiled_kernel_space_boundaries()
        self.setup_modules_and_handlers()

        # Access head of ftrace_ops_list
        ftrace_ops_head = self.vmlinux.object_from_symbol(
            "ftrace_ops_list"
        ).dereference()
        local_ftrace_ops_list = []
        results = []

        while True:
            local_ftrace_ops_list.append(ftrace_ops_head)
            if ftrace_ops_head.next.is_readable():
                ftrace_ops_head = ftrace_ops_head.next.dereference()
            else:
                break

        for i, ftrace_ops in enumerate(local_ftrace_ops_list):
            self._progress_callback(
                (i / len(local_ftrace_ops_list)) * 100, f"Scanning ftrace_ops_list..."
            )
            try:
                parse_result = self.parse_ftrace_ops(ftrace_ops=ftrace_ops)
                if parse_result:
                    results.append((0, parse_result))
            except Exception as e:
                vollog.exception(f"Unhandled exception : {e}")

        # Preferred to "yield", otherwise progress_callback and results overlap...
        return results

    def parse_ftrace_ops(self, ftrace_ops):
        """Main parser for an ftrace_ops struct"""
        ftrace_ops_addr = ftrace_ops.vol.offset
        ftrace_func_entries = self.walk_to_ftrace_func_entry(ftrace_ops)

        for ftrace_func_entry in ftrace_func_entries:
            callback = int(ftrace_ops.func)
            hook_symbols = wrapper_get_symbols_by_absolute_location(
                self.vmlinux, ftrace_func_entry.ip.cast("pointer")
            )

            # Avoid running the aggressive module finder twice for an address, if it wasn't found previously
            if self.checked_callbacks.get(callback):
                module_name = self.checked_callbacks[callback]
            else:
                module_name = self.wrapper_lookup_module_address(callback)
                self.checked_callbacks[callback] = module_name

            # Useful information allowing to detect if a module was inserted dynamically or if it is part of the compiled kernel
            callback_out_of_kernel_range = (
                callback < self.kernel_space_start or callback > self.kernel_space_end
            )
            ftrace_flags = self.parse_ftrace_flags(ftrace_ops.flags)

            ### Format results ###
            callback_symbol = UNKNOWN
            f_module = UNKNOWN
            # Fetch more informations about the module
            if module_name != UNKNOWN:
                module_obj = get_module_object_from_name(module_name, self.modules)
                if module_obj is None:
                    continue

                module_address = module_obj.vol.offset
                f_module = f"{hex(module_address)} [{module_name}]"
                callback_symbol = module_obj.get_symbol_by_address(callback) or UNKNOWN

            result = (
                format_hints.Hex(ftrace_ops_addr),
                f"{hex(callback)} [{callback_symbol}]",
                str(hook_symbols),
                f_module,
                callback_out_of_kernel_range,
            )

            if self.config.get("show_ftrace_flags"):
                result += (str(ftrace_flags),)

            return result

    def parse_ftrace_flags(self, ftrace_flags_value: int):
        """Parse flags set on a hook structure"""
        ret = []
        for couple in FTRACEFLAGS:
            if ftrace_flags_value & couple.value:
                ret.append(couple.name)

        return ret

    def walk_to_ftrace_func_entry(self, ftrace_ops):
        """Function wrapping the process of walking to every ftrace_func_entry for an ftrace_ops"""

        # Decompose walk for better debugging
        try:
            func_hash = ftrace_ops.func_hash.dereference()
        except:
            vollog.debug(
                f"No func_hash for ftrace_ops@{hex(ftrace_ops.vol.offset)}, skipping..."
            )
            return None

        try:
            filter_hash = func_hash.filter_hash.dereference()
        except:
            vollog.debug(
                f"No func_hash.filter_hash for ftrace_ops@{hex(ftrace_ops.vol.offset)}, skipping..."
            )
            return None

        try:
            bucket_head = filter_hash.buckets.dereference().first.dereference()
        except exceptions.InvalidAddressException:
            vollog.debug(
                f"No func_hash.filter_hash.buckets for ftrace_ops@{hex(ftrace_ops.vol.offset)}, skipping..."
            )
            return None

        while True:
            yield bucket_head.cast("ftrace_func_entry")
            if bucket_head.next.is_readable():
                bucket_head = bucket_head.next.dereference()
            else:
                break

    def set_compiled_kernel_space_boundaries(self):
        """Set compiler kernel address spaces. Preferred to linux.LinuxUtilities.generate_kernel_handler_info()[0] for convenience"""
        self.kernel_space_start = self.vmlinux.get_absolute_symbol_address("_stext")
        self.kernel_space_end = self.vmlinux.get_absolute_symbol_address("_etext")

    def get_all_handlers(self):
        """Concatenate all handlers ("/proc/modules", "/sys/module/" and "unlinked kobject modules from sysfs hierarchy")"""
        return self.proc_handlers + self.sysfs_handlers + self.sysfs_unlinked_handlers

    def wrapper_lookup_module_address(self, leaked_address: int):
        # Detect module name based on leaked_address address
        module_name, _ = linux.LinuxUtilities.lookup_module_address(
            self.vmlinux,
            self.get_all_handlers(),
            leaked_address,
        )
        # Aggressive module finder, for deeply hidden rootkits (try to detect usage of kobject_del)
        if module_name == UNKNOWN:
            sysfs_unlinked_modules = check_unlinked_modules.Check_unlinked_modules(
                self.context, self.config_path
            )._generator(self.sysfs_handlers, self.sysfs_modules, leaked_address)
            if sysfs_unlinked_modules:
                sysfs_unlinked_modules = [m[1] for m in sysfs_unlinked_modules]
                self.sysfs_unlinked_handlers = (
                    linux.LinuxUtilities.generate_kernel_handler_info(
                        self.context, self.vmlinux.name, sysfs_unlinked_modules
                    )
                )
                self.modules.extend(sysfs_unlinked_modules)

                # Search handlers again with the new informations, to see if leaked_address fits now
                module_name, _ = linux.LinuxUtilities.lookup_module_address(
                    self.vmlinux,
                    self.get_all_handlers(),
                    leaked_address,
                )

        return module_name

    def setup_modules_and_handlers(self):
        # Get /proc/modules and /sys/module/ listed modules
        self.proc_modules = list(
            lsmod.Lsmod.list_modules(self.context, self.vmlinux.name)
        )
        self.sysfs_modules = list(
            check_unlinked_modules.Check_unlinked_modules.wrapper_get_sysfs_modules(
                self.context, self.config_path, self.vmlinux.name
            )
        )
        # Calculate boundaries for each module
        self.proc_handlers = linux.LinuxUtilities.generate_kernel_handler_info(
            self.context, self.vmlinux.name, self.proc_modules
        )
        self.sysfs_handlers = linux.LinuxUtilities.generate_kernel_handler_info(
            self.context, self.vmlinux.name, self.sysfs_modules
        )
        self.sysfs_unlinked_handlers = []
        self.modules = self.proc_modules + self.sysfs_modules


## UTILITIES ##
def wrapper_get_symbols_by_absolute_location(
    vmlinux: interfaces.context.ModuleInterface, target_address: int
):
    """List symbols related to a specified address"""

    symbols = list(vmlinux.get_symbols_by_absolute_location(target_address))

    if len(symbols) == 0:
        return "UNKNOWN"
    else:
        return [
            symbol if constants.BANG not in symbol else symbol.split(constants.BANG)[1]
            for symbol in symbols
        ]


def get_module_object_from_name(
    wanted_module_name: str, modules: list
) -> Optional[linux.extensions.module]:
    """Return a module object based on a module name"""
    for m in modules:
        if utility.array_to_string(m.name) == wanted_module_name:
            return m
