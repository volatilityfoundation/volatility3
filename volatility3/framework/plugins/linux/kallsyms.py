# This file is Copyright 2025 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
import logging
from typing import List, Union

from volatility3.framework import interfaces, renderers
from volatility3.framework.interfaces import plugins
from volatility3.framework.configuration import requirements
from volatility3.framework.renderers import format_hints
from volatility3.framework.constants import architectures
from volatility3.framework.symbols.linux import kallsyms


vollog = logging.getLogger(__name__)


class Kallsyms(plugins.PluginInterface):
    """Kallsyms symbols enumeration plugin.

    If no arguments are provided, all symbols are included: core, modules, ftrace, and BPF.
    Alternatively, you can use any combination of --core, --modules, --ftrace, and --bpf
    to customize the output.
    """

    _required_framework_version = (2, 19, 0)

    _version = (1, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Linux kernel",
                architectures=architectures.LINUX_ARCHS,
            ),
            requirements.VersionRequirement(
                name="Kallsyms", component=kallsyms.Kallsyms, version=(1, 0, 0)
            ),
            requirements.BooleanRequirement(
                name="core",
                description="Include core symbols",
                default=False,
                optional=True,
            ),
            requirements.BooleanRequirement(
                name="modules",
                description="Include module symbols",
                default=False,
                optional=True,
            ),
            requirements.BooleanRequirement(
                name="ftrace",
                description="Include ftrace symbols",
                default=False,
                optional=True,
            ),
            requirements.BooleanRequirement(
                name="bpf",
                description="Include BPF symbols",
                default=False,
                optional=True,
            ),
        ]

    def _get_symbol_size(
        self, kassymbol: kallsyms.KASSymbol
    ) -> Union[int, interfaces.renderers.BaseAbsentValue]:
        # Symbol sizes are calculated using the address of the next non-aliased
        # symbol or the end of the kernel text area _end/_etext. However, some kernel
        # symbols live beyond that area. For these symbols, the size will be negative,
        # resulting in incorrect values. Unfortunately, there isn't much that can be done
        # in such cases.
        # See comments on .init.scratch in arch/x86/kernel/vmlinux.lds.S for details
        if not kassymbol or not kassymbol.size:
            return renderers.NotAvailableValue()

        return kassymbol.size if kassymbol.size >= 0 else renderers.NotAvailableValue()

    def _generator(self):
        module_name = self.config["kernel"]
        vmlinux = self.context.modules[module_name]

        kas = kallsyms.Kallsyms(
            context=self.context,
            layer_name=vmlinux.layer_name,
            module_name=module_name,
        )

        include_core = self.config.get("core", False)
        include_modules = self.config.get("modules", False)
        include_ftrace = self.config.get("ftrace", False)
        include_bpf = self.config.get("bpf", False)

        symbols_flags = (include_core, include_modules, include_ftrace, include_bpf)
        if not any(symbols_flags):
            include_core = include_modules = include_ftrace = include_bpf = True

        symbol_generators = []

        if include_core:
            symbol_generators.append(kas.get_core_symbols())
        if include_modules:
            symbol_generators.append(kas.get_modules_symbols())
        if include_ftrace:
            symbol_generators.append(kas.get_ftrace_symbols())
        if include_bpf:
            symbol_generators.append(kas.get_bpf_symbols())

        for symbols_generator in symbol_generators:
            for kassymbol in symbols_generator:
                if not kassymbol:
                    continue
                # Symbol sizes are calculated using the address of the next non-aliased
                # symbol or the end of the kernel text area _end/_etext. However, some kernel
                # symbols are located beyond that area, which causes this method to fail for
                # the last symbol, resulting in a negative size.
                # See comments on .init.scratch in arch/x86/kernel/vmlinux.lds.S for details
                symbol_size = self._get_symbol_size(kassymbol)

                if kassymbol.exported is None:
                    exported = renderers.NotAvailableValue()
                else:
                    exported = kassymbol.exported

                fields = (
                    format_hints.Hex(kassymbol.address),
                    kassymbol.type or renderers.NotAvailableValue(),
                    symbol_size,
                    exported,
                    kassymbol.subsystem,
                    kassymbol.module_name,
                    kassymbol.name,
                    kassymbol.type_description or renderers.NotAvailableValue(),
                )
                yield 0, fields

    def run(self):
        headers = [
            ("Addr", format_hints.Hex),
            ("Type", str),
            ("Size", int),
            ("Exported", bool),
            ("SubSystem", str),
            ("ModuleName", str),
            ("SymbolName", str),
            ("Description", str),
        ]
        return renderers.TreeGrid(headers, self._generator())
