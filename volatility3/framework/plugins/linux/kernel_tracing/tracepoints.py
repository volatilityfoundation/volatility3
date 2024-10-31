# This file is Copyright 2023 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
import logging
from typing import List
from volatility3.plugins.linux import lsmod, check_unlinked_modules
from volatility3.framework import constants, exceptions, interfaces
from volatility3.framework.configuration import requirements
from volatility3.framework.renderers import TreeGrid
from volatility3.framework.symbols import linux
from volatility3.framework.objects import utility

vollog = logging.getLogger(__name__)
UNKNOWN = "UNKNOWN"


class Check_tracepoints(interfaces.plugins.PluginInterface):
    """Detect tracepoints hooking"""

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
            requirements.PluginRequirement(
                name="check_modules", plugin=lsmod.Lsmod, version=(2, 0, 0)
            ),
        ]

    def run(self):
        """Plugin output format :

        Tracepoint : "tracepoint offset" ["tracepoint name"]
        Probe : "probe offset" ["probe name"]
        Module :  hex("module offset") ["associated module"] | "UNKNOWN"
        Probe out of kernel .text : True | False
        """

        columns = [
            ("tracepoint", str),
            ("Probe", str),
            ("Module", str),
            ("Probe out of kernel .text", bool),
        ]

        return TreeGrid(
            columns,
            self._generator(),
        )

    def _generator(self):
        self.vmlinux = self.context.modules[self.config["kernel"]]
        if not self.vmlinux.has_symbol("__start___tracepoints_ptrs"):
            raise exceptions.SymbolError(
                "__start___tracepoints_ptrs",
                self.vmlinux.symbol_table_name,
                'The provided symbol table does not include the "__start___tracepoints_ptrs" symbol. This means you are either analyzing an unsupported kernel version or that your symbol table is corrupt.',
            )

        self.checked_probes = {}
        self.set_compiled_kernel_space_boundaries()
        self.setup_modules_and_handlers()

        k_config_have_arch_prel32_relocations = False
        tracepoints = []
        tracepoints_start = self.vmlinux.object_from_symbol(
            "__start___tracepoints_ptrs"
        )
        tracepoints_end = self.vmlinux.object_from_symbol("__stop___tracepoints_ptrs")
        tracepoints_size_raw = tracepoints_end.vol.offset - tracepoints_start.vol.offset

        # Determine if tracepoints array contains a set of valid absolute pointers, or a set of relative pointers (represented by 32 bits integers).
        # See https://elixir.bootlin.com/linux/v6.6/source/include/linux/tracepoint.h#L113 for references.
        tracepoints_ptrs = utility.array_of_pointers(
            tracepoints_start,
            tracepoints_size_raw // 8,
            self.vmlinux.symbol_table_name + constants.BANG + "tracepoint",
            self.context,
        )
        # Check two different pointers
        if (
            not tracepoints_ptrs[0].is_readable()
            or not tracepoints_ptrs[1].is_readable()
        ):
            k_config_have_arch_prel32_relocations = True
        else:
            for tracepoint_ptr in tracepoints_ptrs:
                tracepoints.append(tracepoint_ptr.dereference())

        vollog.debug(
            f"CONFIG_HAVE_ARCH_PREL32_RELOCATIONS was determined to be {k_config_have_arch_prel32_relocations}"
        )

        if k_config_have_arch_prel32_relocations:
            subtype_int = self.vmlinux.context.symbol_space.get_type(
                self.vmlinux.symbol_table_name + constants.BANG + "int"
            )
            tracepoints_relative_offsets = tracepoints_start.cast(
                "array", count=tracepoints_size_raw // 4, subtype=subtype_int
            )
            # Based on "offset_to_ptr()". See https://elixir.bootlin.com/linux/v6.6/source/include/linux/compiler.h#L223 for references.
            for relative_offset in tracepoints_relative_offsets:
                tracepoint = self.vmlinux.object(
                    "tracepoint",
                    relative_offset + relative_offset.vol.offset,
                    absolute=True,
                )
                tracepoints.append(tracepoint)

        results = []
        for i, tracepoint in enumerate(tracepoints):
            self._progress_callback(
                (i / len(tracepoints)) * 100, f"Iterating over tracepoints..."
            )
            # Ignore tracepoints without attached probes
            if not tracepoint.funcs.is_readable():
                continue

            try:
                parse_result = self.parse_tracepoint(tracepoint)
                results.append((0, parse_result))
            except Exception as e:
                vollog.exception(f"Unhandled exception : {e}")

        # Preferred to "yield", otherwise progress_callback and results overlap...
        return results

    def parse_tracepoint(self, tracepoint):
        tracepoint_name = utility.pointer_to_string(tracepoint.name, count=512)
        tracepoint_offset = tracepoint.vol.offset
        probe_handler_address = tracepoint.funcs.dereference().func

        # Avoid running the aggressive module finder twice for an address, if it wasn't found previously
        if self.checked_probes.get(probe_handler_address):
            module_name = self.checked_probes[probe_handler_address]
        else:
            module_name = self.wrapper_lookup_module_address(probe_handler_address)
            self.checked_probes[probe_handler_address] = module_name

        # Useful information allowing to detect if a module was inserted dynamically or if it is part of the compiled kernel
        probe_out_of_kernel_range = (
            probe_handler_address < self.kernel_space_start
            or probe_handler_address > self.kernel_space_end
        )

        ### Format results ###
        probe_handler_address_symbol = UNKNOWN
        f_module = UNKNOWN
        # Fetch more informations about the module
        if module_name != UNKNOWN:
            module_obj = get_module_object_from_name(module_name, self.modules)
            module_address = module_obj.vol.offset
            f_module = f"{hex(module_address)} [{module_name}]"
            probe_handler_address_symbol = (
                module_obj.get_symbol_by_address(probe_handler_address) or UNKNOWN
            )

        results = (
            f"{hex(tracepoint_offset)} [{tracepoint_name}]",
            f"{hex(probe_handler_address)} [{probe_handler_address_symbol}]",
            f_module,
            probe_out_of_kernel_range,
        )
        return results

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
def get_module_object_from_name(
    wanted_module_name: str, modules: list
) -> linux.extensions.module:
    """Return a module object based on a module name"""
    for m in modules:
        if utility.array_to_string(m.name) == wanted_module_name:
            return m
