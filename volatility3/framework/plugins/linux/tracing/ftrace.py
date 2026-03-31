# This file is Copyright 2025 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

# Public researches: https://i.blackhat.com/USA21/Wednesday-Handouts/us-21-Fixing-A-Memory-Forensics-Blind-Spot-Linux-Kernel-Tracing-wp.pdf

import logging
from typing import List, Generator
from enum import Enum
from dataclasses import dataclass

import volatility3.framework.symbols.linux.utilities.modules as linux_utilities_modules
from volatility3.framework import constants, exceptions, interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.renderers import format_hints
from volatility3.framework.constants import architectures

vollog = logging.getLogger(__name__)


# https://docs.python.org/3.13/library/enum.html#enum.IntFlag
class FtraceOpsFlags(Enum):
    """Denote the state of an ftrace_ops struct.
    Based on https://elixir.bootlin.com/linux/v6.13-rc3/source/include/linux/ftrace.h#L255.
    """

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
    FTRACE_OPS_FL_SUBOP = 1 << 18


@dataclass
class ParsedFtraceOps:
    """Parsed ftrace_ops struct representation, containing a selection of forensics valuable
    information."""

    ftrace_ops_offset: int
    callback_symbol: str
    callback_address: int
    hooked_symbols: str
    module_name: str
    module_address: int
    flags: str


class CheckFtrace(interfaces.plugins.PluginInterface):
    """Detect ftrace hooking

    Investigate the ftrace infrastructure to uncover kernel attached callbacks, which can be leveraged
    to hook kernel functions and modify their behaviour."""

    _version = (4, 0, 0)
    _required_framework_version = (2, 19, 0)

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
                component=linux_utilities_modules.Modules,
                version=(3, 0, 0),
            ),
            requirements.VersionRequirement(
                name="linux_utilities_module_gatherers",
                component=linux_utilities_modules.ModuleGatherers,
                version=(1, 0, 0),
            ),
            requirements.BooleanRequirement(
                name="show_ftrace_flags",
                description="Show ftrace flags associated with an ftrace_ops struct",
                optional=True,
                default=False,
            ),
        ]

    @classmethod
    def extract_hash_table_filters(
        cls,
        ftrace_ops: interfaces.objects.ObjectInterface,
    ) -> Generator[interfaces.objects.ObjectInterface, None, None]:
        """Wrap the process of walking to every ftrace_func_entry of an ftrace_ops.
        Those are stored in a hash table of filters that indicates the addresses hooked.

        Args:
            ftrace_ops: The ftrace_ops struct to walk through

        Return, None, None:
            An iterable of ftrace_func_entry structs
        """

        if hasattr(ftrace_ops, "func_hash"):
            ftrace_hash = ftrace_ops.func_hash.filter_hash
        else:
            ftrace_hash = ftrace_ops.filter_hash

        try:
            current_bucket_ptr = ftrace_hash.buckets.first
        except exceptions.InvalidAddressException:
            vollog.log(
                constants.LOGLEVEL_VV,
                f"ftrace_func_entry list of ftrace_ops@{ftrace_ops.vol.offset:#x} is empty/invalid. Skipping it...",
            )
            return

        while current_bucket_ptr.is_readable():
            yield current_bucket_ptr.dereference().cast("ftrace_func_entry")
            current_bucket_ptr = current_bucket_ptr.next

    @classmethod
    def parse_ftrace_ops(
        cls,
        context: interfaces.context.ContextInterface,
        kernel_module_name: str,
        known_modules: List[linux_utilities_modules.ModuleInfo],
        ftrace_ops: interfaces.objects.ObjectInterface,
    ) -> Generator[ParsedFtraceOps, None, None]:
        """Parse an ftrace_ops struct to highlight ftrace kernel hooking.
        Iterates over embedded ftrace_func_entry entries, which point to hooked memory areas.

        Args:
            known_modules: A dict of known modules, used to locate callbacks origin. Typically obtained through run_modules_scanners().
            ftrace_ops: The ftrace_ops struct to parse

        Yields:
            An iterable of ParsedFtraceOps dataclasses, containing a selection of useful fields (callback, hook, module) related to an ftrace_ops struct
        """
        kernel = context.modules[kernel_module_name]
        callback = ftrace_ops.func

        mod_info, callback_symbol = (
            linux_utilities_modules.Modules.module_lookup_by_address(
                context,
                kernel_module_name,
                known_modules,
                callback,
            )
        )

        if mod_info:
            module_address = mod_info.start
            module_name = mod_info.name
        else:
            callback_symbol = module_address = module_name = None

            vollog.debug(
                f"Could not determine ftrace_ops@{ftrace_ops.vol.offset:#x} callback {callback:#x} module origin.",
            )

        # Iterate over ftrace_func_entry list
        for ftrace_func_entry in cls.extract_hash_table_filters(ftrace_ops):
            hook_address = ftrace_func_entry.ip.cast("pointer")

            # Determine the symbols associated with a hook
            hooked_symbols = kernel.get_symbols_by_absolute_location(hook_address)
            hooked_symbols = ",".join(
                [
                    hooked_symbol.split(constants.BANG)[-1]
                    for hooked_symbol in hooked_symbols
                ]
            )
            formatted_ftrace_flags = ",".join(
                [flag.name for flag in FtraceOpsFlags if flag.value & ftrace_ops.flags]
            )
            yield ParsedFtraceOps(
                ftrace_ops.vol.offset,
                callback_symbol,
                callback,
                hooked_symbols,
                module_name,
                module_address,
                formatted_ftrace_flags,
            )

    @classmethod
    def iterate_ftrace_ops_list(
        cls, context: interfaces.context.ContextInterface, kernel_name: str
    ) -> Generator[interfaces.objects.ObjectInterface, None, None]:
        """Iterate over (ftrace_ops *)ftrace_ops_list.

        Returns:
            An iterable of ftrace_ops structs
        """
        kernel = context.modules[kernel_name]
        current_frace_ops_ptr = kernel.object_from_symbol("ftrace_ops_list")
        ftrace_list_end = kernel.object_from_symbol("ftrace_list_end")

        while current_frace_ops_ptr.is_readable():
            # ftrace_list_end is not considered a valid struct
            # see kernel function test_rec_ops_needs_regs
            if current_frace_ops_ptr != ftrace_list_end.vol.offset:
                yield current_frace_ops_ptr.dereference()
                current_frace_ops_ptr = current_frace_ops_ptr.next
            else:
                break

    def _generator(self):
        kernel_name = self.config["kernel"]
        kernel = self.context.modules[kernel_name]

        if not kernel.has_symbol("ftrace_ops_list"):
            vollog.error(
                'The provided symbol table does not include the "ftrace_ops_list" symbol. This means you are either analyzing an unsupported kernel version or that your symbol table is corrupted.'
            )
            return

        known_modules = linux_utilities_modules.Modules.run_modules_scanners(
            context=self.context,
            kernel_module_name=self.config["kernel"],
            caller_wanted_gatherers=linux_utilities_modules.ModuleGatherers.all_gatherers_identifier,
        )

        for ftrace_ops in self.iterate_ftrace_ops_list(self.context, kernel_name):
            for ftrace_ops_parsed in self.parse_ftrace_ops(
                self.context,
                kernel_name,
                known_modules,
                ftrace_ops,
            ):
                formatted_results = (
                    format_hints.Hex(ftrace_ops_parsed.ftrace_ops_offset),
                    ftrace_ops_parsed.callback_symbol or renderers.NotAvailableValue(),
                    format_hints.Hex(ftrace_ops_parsed.callback_address),
                    ftrace_ops_parsed.hooked_symbols or renderers.NotAvailableValue(),
                    ftrace_ops_parsed.module_name or renderers.NotAvailableValue(),
                    (
                        format_hints.Hex(ftrace_ops_parsed.module_address)
                        if ftrace_ops_parsed.module_address is not None
                        else renderers.NotAvailableValue()
                    ),
                )
                if self.config["show_ftrace_flags"]:
                    formatted_results += (ftrace_ops_parsed.flags,)
                yield (0, formatted_results)

    def run(self):
        columns = [
            ("ftrace_ops address", format_hints.Hex),
            ("Callback", str),
            ("Callback address", format_hints.Hex),
            ("Hooked symbols", str),
            ("Module", str),
            ("Module address", format_hints.Hex),
        ]

        if self.config.get("show_ftrace_flags"):
            columns.append(("Flags", str))

        return renderers.TreeGrid(
            columns,
            self._generator(),
        )
