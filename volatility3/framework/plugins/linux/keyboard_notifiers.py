# This file is Copyright 2020 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

import logging

import volatility3.framework.symbols.linux.utilities.modules as linux_utilities_modules
from volatility3.framework import interfaces, renderers, exceptions
from volatility3.framework.configuration import requirements
from volatility3.framework.renderers import format_hints
from volatility3.framework.symbols import linux

vollog = logging.getLogger(__name__)


class Keyboard_notifiers(interfaces.plugins.PluginInterface):
    """Parses the keyboard notifier call chain"""

    _required_framework_version = (2, 0, 0)

    @classmethod
    def get_requirements(cls):
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Linux kernel",
                architectures=["Intel32", "Intel64"],
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
            requirements.VersionRequirement(
                name="linuxutils", component=linux.LinuxUtilities, version=(2, 0, 0)
            ),
        ]

    def _generator(self):
        vmlinux = self.context.modules[self.config["kernel"]]

        try:
            knl_addr = vmlinux.object_from_symbol("keyboard_notifier_list")
        except exceptions.SymbolError:
            knl_addr = None

        if not knl_addr:
            raise TypeError(
                "This plugin requires the keyboard_notifier_list structure. "
                "This structure is not present in the supplied symbol table. "
                "This means you are either analyzing an unsupported kernel version or that your symbol table is corrupt."
            )

        if not self.context.layers[vmlinux.layer_name].is_valid(knl_addr.vol.offset):
            vollog.error("The head of the keyboard notifier list is paged out.")
            return

        known_modules = linux_utilities_modules.Modules.run_modules_scanners(
            context=self.context,
            kernel_module_name=self.config["kernel"],
            caller_wanted_gatherers=linux_utilities_modules.ModuleGatherers.all_gatherers_identifier,
        )

        knl = vmlinux.object(
            object_type="atomic_notifier_head",
            offset=knl_addr.vol.offset,
            absolute=True,
        )

        for call_back in linux.LinuxUtilities.walk_internal_list(
            vmlinux, "notifier_block", "next", knl.head
        ):
            call_addr = call_back.notifier_call

            module_info, symbol_name = (
                linux_utilities_modules.Modules.module_lookup_by_address(
                    self.context, vmlinux.name, known_modules, call_addr
                )
            )

            if module_info:
                module_name = module_info.name
            else:
                module_name = renderers.NotAvailableValue()

            yield (
                0,
                [
                    format_hints.Hex(call_addr),
                    module_name,
                    symbol_name or renderers.NotAvailableValue(),
                ],
            )

    def run(self):
        return renderers.TreeGrid(
            [("Address", format_hints.Hex), ("Module", str), ("Symbol", str)],
            self._generator(),
        )
