# This file is Copyright 2020 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

import logging
from typing import List

from volatility3.framework import interfaces, renderers, contexts, symbols
from volatility3.framework.configuration import requirements
from volatility3.framework.renderers import format_hints
from volatility3.framework.symbols import linux
from volatility3.plugins.linux import lsmod

vollog = logging.getLogger(__name__)


class Check_idt(interfaces.plugins.PluginInterface):
    """ Checks if the IDT has been altered """

    _required_framework_version = (1, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.TranslationLayerRequirement(name = 'primary',
                                                     description = 'Memory layer for the kernel',
                                                     architectures = ["Intel32", "Intel64"]),
            requirements.SymbolTableRequirement(name = "vmlinux", description = "Linux kernel symbols"),
            requirements.VersionRequirement(name = 'linuxutils', component = linux.LinuxUtilities, version = (1, 0, 0)),
            requirements.PluginRequirement(name = 'lsmod', plugin = lsmod.Lsmod, version = (1, 0, 0))
        ]

    def _generator(self):
        vmlinux = contexts.Module(self.context, self.config['vmlinux'], self.config['primary'], 0)

        modules = lsmod.Lsmod.list_modules(self.context, self.config['primary'], self.config['vmlinux'])

        handlers = linux.LinuxUtilities.generate_kernel_handler_info(self.context, self.config['primary'],
                                                                     self.config['vmlinux'], modules)

        is_32bit = not symbols.symbol_table_is_64bit(self.context, self.config["vmlinux"])

        idt_table_size = 256

        address_mask = self.context.layers[self.config['primary']].address_mask

        # hw handlers + system call
        check_idxs = list(range(0, 20)) + [128]

        if is_32bit:
            if vmlinux.has_type("gate_struct"):
                idt_type = "gate_struct"
            else:
                idt_type = "desc_struct"
        else:
            if vmlinux.has_type("gate_struct64"):
                idt_type = "gate_struct64"
            elif vmlinux.has_type("gate_struct"):
                idt_type = "gate_struct"
            else:
                idt_type = "idt_desc"

        addrs = vmlinux.object_from_symbol("idt_table")

        table = vmlinux.object(object_type = 'array',
                               offset = addrs.vol.offset,
                               subtype = vmlinux.get_type(idt_type),
                               count = idt_table_size)

        for i in check_idxs:
            ent = table[i]

            if not ent:
                continue

            if hasattr(ent, "Address"):
                idt_addr = ent.Address
            else:
                low = ent.offset_low
                middle = ent.offset_middle

                if hasattr(ent, "offset_high"):
                    high = ent.offset_high
                else:
                    high = 0

                idt_addr = (high << 32) | (middle << 16) | low

                idt_addr = idt_addr & address_mask

            module_name, symbol_name = linux.LinuxUtilities.lookup_module_address(self.context, handlers, idt_addr)

            yield (0, [format_hints.Hex(i), format_hints.Hex(idt_addr), module_name, symbol_name])

    def run(self):
        return renderers.TreeGrid([("Index", format_hints.Hex), ("Address", format_hints.Hex), ("Module", str),
                                   ("Symbol", str)], self._generator())
