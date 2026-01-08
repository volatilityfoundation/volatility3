# This file is Copyright 2020 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

import logging
from typing import List, Optional

import volatility3.framework.symbols.linux.utilities.modules as linux_utilities_modules
from volatility3.framework import interfaces, renderers, symbols
from volatility3.framework.configuration import requirements
from volatility3.framework.renderers import format_hints
from volatility3.framework.symbols import linux

vollog = logging.getLogger(__name__)


class Check_idt(interfaces.plugins.PluginInterface):
    """Checks if the IDT has been altered"""

    _required_framework_version = (2, 0, 0)

    # 2.0.0 - Add versioning at all, add `get_idt_type`
    _version = (2, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
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

    @staticmethod
    def get_idt_type(context, vmlinux_name) -> Optional[str]:
        """
        Determines the IDT type for this symbol table or returns None

        The original version ended clauses with an `else` leading to bad fall through
        of returning a type that did not exist in the symbol table.

        Future updates should not leave fall through cases to avoid this repeating.
        """

        vmlinux = context.modules[vmlinux_name]

        is_32bit = not symbols.symbol_table_is_64bit(context, vmlinux.symbol_table_name)

        # These are in a specific order. Only append to the lists going forward
        # or ask Andrew to run tests before merging.
        if is_32bit:
            idt_types = ["gate_struct", "desc_struct", "gate_struct32"]
        else:
            idt_types = ["gate_struct64", "gate_struct", "idt_desc"]

        for idt_type in idt_types:
            if vmlinux.has_type(idt_type):
                return idt_type

        return None

    def _generator(self):
        idt_type = self.get_idt_type(self.context, self.config["kernel"])
        if not idt_type:
            vollog.error(
                "Unable to determine the data structure type for IDT entries. Please file a bug on the GitHub tracker with your kernel version."
            )
            return

        vmlinux = self.context.modules[self.config["kernel"]]

        known_modules = linux_utilities_modules.Modules.run_modules_scanners(
            context=self.context,
            kernel_module_name=self.config["kernel"],
            caller_wanted_gatherers=linux_utilities_modules.ModuleGatherers.all_gatherers_identifier,
        )

        idt_table_size = 256

        kernel_layer = self.context.layers[vmlinux.layer_name]

        address_mask = kernel_layer.address_mask

        # hw handlers + system call
        check_idxs = list(range(20)) + [128]

        addrs = vmlinux.object_from_symbol("idt_table")

        table = vmlinux.object(
            object_type="array",
            offset=addrs.vol.offset,
            subtype=vmlinux.get_type(idt_type),
            count=idt_table_size,
            absolute=True,
        )

        for i in check_idxs:
            ent = table[i]

            if not ent or not kernel_layer.is_valid(ent.vol.offset):
                continue

            if hasattr(ent, "a"):
                idt_addr = (ent.b & 0xFFFF0000) | (ent.a & 0x0000FFFF)
            else:
                low = ent.offset_low
                middle = ent.offset_middle

                # offset_high is for 64bit systems
                if hasattr(ent, "offset_high"):
                    high = ent.offset_high
                else:
                    high = 0

                idt_addr = (high << 32) | (middle << 16) | low

                idt_addr = idt_addr & address_mask

            # 0 means unintialized/unused, not a rootkit
            if idt_addr == 0:
                module_name = renderers.NotAvailableValue()
                symbol_name = renderers.NotAvailableValue()
            else:
                module_info, symbol_name = (
                    linux_utilities_modules.Modules.module_lookup_by_address(
                        self.context, vmlinux.name, known_modules, idt_addr
                    )
                )

                if module_info:
                    module_name = module_info.name
                else:
                    module_name = renderers.NotAvailableValue()

            yield (
                0,
                [
                    format_hints.Hex(i),
                    format_hints.Hex(idt_addr),
                    module_name,
                    symbol_name or renderers.NotAvailableValue(),
                ],
            )

    def run(self):
        return renderers.TreeGrid(
            [
                ("Index", format_hints.Hex),
                ("Address", format_hints.Hex),
                ("Module", str),
                ("Symbol", str),
            ],
            self._generator(),
        )
