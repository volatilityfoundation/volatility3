# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

import logging
from typing import List, Iterator, Any

from volatility3.framework import exceptions, interfaces
from volatility3.framework import renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.interfaces import plugins
from volatility3.framework.objects import utility
from volatility3.framework.renderers import format_hints
from volatility3.framework.symbols import mac
from volatility3.plugins.mac import lsmod

vollog = logging.getLogger(__name__)


class Trustedbsd(plugins.PluginInterface):
    """Checks for malicious trustedbsd modules"""

    _required_framework_version = (2, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Kernel module for the OS",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.VersionRequirement(
                name="macutils", component=mac.MacUtilities, version=(1, 3, 0)
            ),
            requirements.VersionRequirement(
                name="lsmod", component=lsmod.Lsmod, version=(2, 0, 0)
            ),
        ]

    def _generator(self, mods: Iterator[Any]):
        kernel = self.context.modules[self.config["kernel"]]

        handlers = mac.MacUtilities.generate_kernel_handler_info(
            self.context, kernel.layer_name, kernel, mods
        )

        policy_list = kernel.object_from_symbol(symbol_name="mac_policy_list").cast(
            "mac_policy_list"
        )

        entries = kernel.object(
            object_type="array",
            offset=policy_list.entries.dereference().vol.offset,
            subtype=kernel.get_type("mac_policy_list_element"),
            absolute=True,
            count=policy_list.staticmax + 1,
        )

        for i, ent in enumerate(entries):
            # I don't know how this can happen, but the kernel makes this check all over the place
            # the policy isn't useful without any ops so a rootkit can't abuse this
            try:
                mpc = ent.mpc.dereference()
                ops = mpc.mpc_ops.dereference()
            except exceptions.InvalidAddressException:
                continue

            try:
                ent_name = utility.pointer_to_string(mpc.mpc_name, 255)
            except exceptions.InvalidAddressException:
                ent_name = "N/A"

            for check in ops.vol.members:
                call_addr = getattr(ops, check)

                if call_addr is None or call_addr == 0:
                    continue

                module_name, symbol_name = mac.MacUtilities.lookup_module_address(
                    self.context, handlers, call_addr, self.config["kernel"]
                )

                yield (
                    0,
                    (
                        check,
                        ent_name,
                        format_hints.Hex(call_addr),
                        module_name,
                        symbol_name,
                    ),
                )

    def run(self):
        return renderers.TreeGrid(
            [
                ("Member", str),
                ("Policy Name", str),
                ("Handler Address", format_hints.Hex),
                ("Handler Module", str),
                ("Handler Symbol", str),
            ],
            self._generator(
                lsmod.Lsmod.list_modules(self.context, self.config["kernel"])
            ),
        )
