# This file is Copyright 2025 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

# Public researches: https://i.blackhat.com/USA21/Wednesday-Handouts/us-21-Fixing-A-Memory-Forensics-Blind-Spot-Linux-Kernel-Tracing-wp.pdf

import logging
from dataclasses import dataclass
from typing import Iterable, List, Optional

import volatility3.framework.symbols.linux.utilities.modules as linux_utilities_modules
from volatility3.framework import constants, exceptions, interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.constants import architectures
from volatility3.framework.objects import utility
from volatility3.framework.renderers import format_hints

vollog = logging.getLogger(__name__)


@dataclass
class ParsedTracepointFunc:
    """Parsed tracepoint_func struct, containing a selection of forensics valuable
    information."""

    tracepoint_name: str
    tracepoint_address: int
    probe_name: str
    probe_address: int
    probe_priority: int
    module_name: str
    module_address: int


class CheckTracepoints(interfaces.plugins.PluginInterface):
    """Detect tracepoints hooking

    Investigate the tracepoints subsystem to uncover kernel attached probes, which can be leveraged
    to hook kernel functions and modify their behaviour."""

    _version = (2, 0, 0)
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
        ]

    @classmethod
    def iterate_tracepoint_funcs(
        cls,
        context: interfaces.context.ContextInterface,
        layer_name: str,
        tracepoint: interfaces.objects.ObjectInterface,
    ) -> Optional[Iterable[interfaces.objects.ObjectInterface]]:
        """Extract probes represented by tracepoint_func structs from a
        tracepoint funcs member.

        Args:
            tracepoint: The tracepoint struct to parse

        Yields:
            An iterable of tracepoint_func structs
        """

        layer = context.layers[layer_name]
        # Ignore tracepoints without attached probes
        if not tracepoint.funcs.is_readable():
            return None

        current_tracepoint_func = tracepoint.funcs.dereference()
        # Inspired by kernel's debug_print_probes()
        while (
            layer.is_valid(current_tracepoint_func.vol.offset)
            and current_tracepoint_func.func.is_readable()
        ):
            yield current_tracepoint_func
            current_tracepoint_func = context.object(
                tracepoint.get_symbol_table_name() + constants.BANG + "tracepoint_func",
                layer_name,
                current_tracepoint_func.vol.offset + current_tracepoint_func.vol.size,
            )

    @classmethod
    def parse_tracepoint(
        cls,
        context: interfaces.context.ContextInterface,
        kernel_module_name: str,
        known_modules: List[linux_utilities_modules.ModuleInfo],
        tracepoint: interfaces.objects.ObjectInterface,
        run_hidden_modules: bool = True,
    ) -> Optional[Iterable[ParsedTracepointFunc]]:
        """Parse a tracepoint struct to highlight tracepoints kernel hooking.

        Args:
            known_modules: A dict of known modules, used to locate callbacks origin. Typically obtained through run_modules_scanners().
            tracepoint: The tracepoint struct to parse
            run_hidden_modules: Whether to run the hidden_modules plugin or not. Note: it won't be run, even if specified, \
            if the "hidden_modules" key is present in known_modules.

        Yields:
            An iterable of ParsedTracepointFunc dataclasses, containing a selection of useful fields related to a tracepoint struct
        """
        kernel = context.modules[kernel_module_name]

        for tracepoint_func in cls.iterate_tracepoint_funcs(
            context, kernel.layer_name, tracepoint
        ):
            try:
                tracepoint_name = utility.pointer_to_string(tracepoint.name, count=512)
            except exceptions.InvalidAddressException:
                vollog.debug(
                    f"Tracepoint function at {tracepoint.vol.offset:#x} is smeared."
                )
                continue

            probe_handler_address = tracepoint_func.func
            probe_handler_symbol = module_address = module_name = None

            # Try to lookup within the known modules if the probe_handler address fits
            mod_info, probe_handler_symbol = (
                linux_utilities_modules.Modules.module_lookup_by_address(
                    context,
                    kernel_module_name,
                    known_modules,
                    probe_handler_address,
                )
            )

            # Fetch more information about the module
            if mod_info is not None:
                module_address = mod_info.offset
                module_name = mod_info.name
            else:
                vollog.debug(
                    f"Could not determine tracepoint@{tracepoint.vol.offset:#x} probe handler {probe_handler_address:#x} module origin.",
                )

            if hasattr(tracepoint_func, "prio"):
                prio = tracepoint_func.prio
            else:
                prio = None

            yield ParsedTracepointFunc(
                tracepoint_name,
                tracepoint.vol.offset,
                probe_handler_symbol,
                probe_handler_address,
                prio,
                module_name,
                module_address,
            )

    @classmethod
    def iterate_tracepoints_array(
        cls, context: interfaces.context.ContextInterface, kernel_name: str
    ) -> List[interfaces.objects.ObjectInterface]:
        """Iterate over (tracepoint_ptr_t *)__start___tracepoints_ptrs.
        Handles CONFIG_HAVE_ARCH_PREL32_RELOCATIONS.

        Returns:
            A list of tracepoint structs
        """

        kernel = context.modules[kernel_name]

        tracepoints = []
        tracepoints_start = kernel.object_from_symbol("__start___tracepoints_ptrs")
        tracepoints_end = kernel.get_absolute_symbol_address(
            "__stop___tracepoints_ptrs"
        )
        tracepoints_array_size = tracepoints_end - tracepoints_start.vol.offset
        # kernel's tracepoint_ptr_deref() and tracepoint_ptr_t
        # adjust depending on the use of PC-relative addressing
        # or not.
        # Relocation is commonly used to store pointers as offsets
        # relative to their own address rather than absolute addresses/pointers.
        config_have_arch_prel32_relocations = (
            tracepoints_start.vol.subtype.type_name
            == kernel.symbol_table_name + constants.BANG + "int"
        )
        if config_have_arch_prel32_relocations:
            tracepoints_relative_offsets = tracepoints_start.cast(
                "array",
                count=tracepoints_array_size // kernel.get_type("int").size,
                subtype=kernel.get_type("int"),
            )
            for relative_offset in tracepoints_relative_offsets:
                # relative_offset is the value stored at relative_offset.vol.offset
                # See kernel's offset_to_ptr(). Example:
                # 0xffff9da125e0 = 0x7af138        + 0xffff9d2634a8
                absolute_address = relative_offset + relative_offset.vol.offset
                tracepoint = kernel.object(
                    "tracepoint",
                    absolute_address,
                    absolute=True,
                )
                tracepoints.append(tracepoint)
        else:
            tracepoints = utility.array_of_pointers(
                tracepoints_start,
                tracepoints_array_size // kernel.get_type("pointer").size,
                kernel.symbol_table_name + constants.BANG + "tracepoint",
                context,
            )

        return tracepoints

    def _generator(self):
        kernel_name = self.config["kernel"]
        kernel = self.context.modules[kernel_name]
        kernel_layer = self.context.layers[kernel.layer_name]

        if not kernel.has_symbol("__start___tracepoints_ptrs"):
            vollog.error(
                'The provided symbol table does not include the "__start___tracepoints_ptrs" symbol.'
                "This means you are either analyzing an unsupported kernel version or that your symbol table is corrupted."
            )
            return

        known_modules = linux_utilities_modules.Modules.run_modules_scanners(
            context=self.context,
            kernel_module_name=self.config["kernel"],
            caller_wanted_gatherers=linux_utilities_modules.ModuleGatherers.all_gatherers_identifier,
        )
        tracepoints = self.iterate_tracepoints_array(self.context, kernel_name)

        for tracepoint in tracepoints:
            if not kernel_layer.is_valid(tracepoint.vol.offset):
                continue

            for tracepoint_parsed in self.parse_tracepoint(
                self.context, kernel_name, known_modules, tracepoint
            ):
                formatted_results = (
                    tracepoint_parsed.tracepoint_name,
                    format_hints.Hex(tracepoint_parsed.tracepoint_address),
                    tracepoint_parsed.probe_name or renderers.NotAvailableValue(),
                    format_hints.Hex(tracepoint_parsed.probe_address),
                    tracepoint_parsed.probe_priority or renderers.NotAvailableValue(),
                    tracepoint_parsed.module_name or renderers.NotAvailableValue(),
                    (
                        format_hints.Hex(tracepoint_parsed.module_address)
                        if tracepoint_parsed.module_address is not None
                        else renderers.NotAvailableValue()
                    ),
                )
                yield (
                    0,
                    formatted_results,
                )

    def run(self):
        columns = [
            ("tracepoint", str),
            ("tracepoint address", format_hints.Hex),
            ("Probe", str),
            ("Probe address", format_hints.Hex),
            ("Probe priority", int),
            ("Module", str),
            ("Module address", format_hints.Hex),
        ]

        return renderers.TreeGrid(
            columns,
            self._generator(),
        )
