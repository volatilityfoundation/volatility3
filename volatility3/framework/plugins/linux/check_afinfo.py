# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
"""A module containing a collection of plugins that produce data typically
found in Linux's /proc file system."""
import logging
from typing import List

from volatility3.framework import exceptions, interfaces
from volatility3.framework import renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.interfaces import plugins
from volatility3.framework.renderers import format_hints

vollog = logging.getLogger(__name__)


class Check_afinfo(plugins.PluginInterface):
    """Verifies the operation function pointers of network protocols."""

    _required_framework_version = (2, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Linux kernel",
                architectures=["Intel32", "Intel64"],
            ),
        ]

    # returns whether the symbol is found within the kernel (system.map) or not
    def _is_known_address(self, handler_addr):
        symbols = list(self.context.symbol_space.get_symbols_by_location(handler_addr))

        return len(symbols) > 0

    def _check_members(self, var_ops, var_name, members):
        for check in members:
            # redhat-specific garbage
            if check.startswith("__UNIQUE_ID_rh_kabi_hide"):
                continue

            if check == "write":
                addr = var_ops.member(attr="write")
            else:
                addr = getattr(var_ops, check)

            if addr and addr != 0 and not self._is_known_address(addr):
                yield check, addr

    def _check_afinfo(self, var_name, var, op_members, seq_members):
        # check if object has a least one of the members used for analysis by this function
        required_members = ["seq_fops", "seq_ops", "seq_show"]
        has_required_member = any(
            [var.has_member(member) for member in required_members]
        )
        if not has_required_member:
            vollog.debug(
                f"{var_name} object at {hex(var.vol.offset)} had none of the required members: {', '.join([member for member in required_members])}"
            )
            raise exceptions.PluginRequirementException

        if var.has_member("seq_fops"):
            for hooked_member, hook_address in self._check_members(
                var.seq_fops, var_name, op_members
            ):
                yield var_name, hooked_member, hook_address

        # newer kernels
        if var.has_member("seq_ops"):
            for hooked_member, hook_address in self._check_members(
                var.seq_ops, var_name, seq_members
            ):
                yield var_name, hooked_member, hook_address

        # this is the most commonly hooked member by rootkits, so a force a check on it
        else:
            if var.has_member("seq_show"):
                if not self._is_known_address(var.seq_show):
                    yield var_name, "show", var.seq_show

    def _generator(self):
        vmlinux = self.context.modules[self.config["kernel"]]

        op_members = vmlinux.get_type("file_operations").members
        seq_members = vmlinux.get_type("seq_operations").members

        tcp = ("tcp_seq_afinfo", ["tcp6_seq_afinfo", "tcp4_seq_afinfo"])
        udp = (
            "udp_seq_afinfo",
            [
                "udplite6_seq_afinfo",
                "udp6_seq_afinfo",
                "udplite4_seq_afinfo",
                "udp4_seq_afinfo",
            ],
        )
        protocols = [tcp, udp]

        # used to track the calls to _check_afinfo and the
        # number of errors produced due to missing members
        symbols_checked = set()
        symbols_with_errors = set()

        # loop through all symbols
        for struct_type, global_vars in protocols:
            for global_var_name in global_vars:
                # this will lookup fail for the IPv6 protocols on kernels without IPv6 support
                try:
                    global_var = vmlinux.get_symbol(global_var_name)
                except exceptions.SymbolError:
                    continue

                global_var = vmlinux.object(
                    object_type=struct_type, offset=global_var.address
                )

                symbols_checked.add(global_var_name)
                try:
                    for name, member, address in self._check_afinfo(
                        global_var_name, global_var, op_members, seq_members
                    ):
                        yield 0, (name, member, format_hints.Hex(address))
                except exceptions.PluginRequirementException:
                    symbols_with_errors.add(global_var_name)

        # if every call to _check_afinfo failed show a warning
        if symbols_checked == symbols_with_errors:
            vollog.warning(
                "This plugin was not able to check for hooks. This means you are either analyzing an unsupported kernel version or that your symbol table is corrupt."
            )

    def run(self):
        return renderers.TreeGrid(
            [
                ("Symbol Name", str),
                ("Member", str),
                ("Handler Address", format_hints.Hex),
            ],
            self._generator(),
        )
