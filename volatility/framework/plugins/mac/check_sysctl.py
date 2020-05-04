# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
import logging
from typing import List

import volatility
from volatility.framework import exceptions, interfaces
from volatility.framework import renderers, contexts
from volatility.framework.automagic import mac
from volatility.framework.configuration import requirements
from volatility.framework.interfaces import plugins
from volatility.framework.objects import utility
from volatility.framework.renderers import format_hints
from volatility.plugins.mac import lsmod

vollog = logging.getLogger(__name__)


class Check_sysctl(plugins.PluginInterface):
    """Check sysctl handlers for hooks."""

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.TranslationLayerRequirement(name = 'primary',
                                                     description = 'Memory layer for the kernel',
                                                     architectures = ["Intel32", "Intel64"]),
            requirements.SymbolTableRequirement(name = "darwin", description = "Mac kernel symbols"),
            requirements.PluginRequirement(name = 'lsmod', plugin = lsmod.Lsmod, version = (1, 0, 0))
        ]

    def _parse_global_variable_sysctls(self, kernel, name):
        known_sysctls = {
            "hostname": "hostname",
            "nisdomainname": "domainname",
        }

        var_str = ""

        if name in known_sysctls:
            var_name = known_sysctls[name]

            try:
                var_array = kernel.object_from_symbol(symbol_name = var_name)
            except exceptions.SymbolError:
                var_array = None

            if var_array is not None:
                var_str = utility.array_to_string(var_array)

        return var_str

    def _process_sysctl_list(self, kernel, sysctl_list, recursive = 0):
        if type(sysctl_list) == volatility.framework.objects.Pointer:
            sysctl_list = sysctl_list.dereference().cast("sysctl_oid_list")

        sysctl = sysctl_list.slh_first

        if recursive != 0:
            try:
                sysctl = sysctl.oid_link.sle_next.dereference()
            except exceptions.InvalidAddressException:
                return

        while sysctl:
            try:
                name = utility.pointer_to_string(sysctl.oid_name, 128)
            except exceptions.InvalidAddressException:
                name = ""

            if len(name) == 0:
                break

            ctltype = sysctl.get_ctltype()

            try:
                arg1_ptr = sysctl.oid_arg1.dereference().vol.offset
            except exceptions.InvalidAddressException:
                arg1_ptr = 0

            arg1 = sysctl.oid_arg1

            if arg1 == 0 or arg1_ptr == 0:
                val = self._parse_global_variable_sysctls(kernel, name)
            elif ctltype == 'CTLTYPE_NODE':
                if sysctl.oid_handler == 0:
                    for info in self._process_sysctl_list(kernel, sysctl.oid_arg1, recursive = 1):
                        yield info

                val = "Node"

            elif ctltype in ['CTLTYPE_INT', 'CTLTYPE_QUAD', 'CTLTYPE_OPAQUE']:
                try:
                    val = str(arg1.dereference().cast("int"))
                except exceptions.InvalidAddressException:
                    val = "-1"

            elif ctltype == 'CTLTYPE_STRING':
                try:
                    val = utility.pointer_to_string(sysctl.oid_arg1, 64)
                except exceptions.InvalidAddressException:
                    val = ""
            else:
                val = ctltype

            yield (sysctl, name, val)

            try:
                sysctl = sysctl.oid_link.sle_next
            except exceptions.InvalidAddressException:
                break

    def _generator(self):
        kernel = contexts.Module(self._context, self.config['darwin'], self.config['primary'], 0)

        mods = lsmod.Lsmod.list_modules(self.context, self.config['primary'], self.config['darwin'])

        handlers = mac.MacUtilities.generate_kernel_handler_info(self.context, self.config['primary'], kernel, mods)

        sysctl_list = kernel.object_from_symbol(symbol_name = "sysctl__children")

        for sysctl, name, val in self._process_sysctl_list(kernel, sysctl_list):
            try:
                check_addr = sysctl.oid_handler
            except exceptions.InvalidAddressException:
                continue

            module_name, symbol_name = mac.MacUtilities.lookup_module_address(self.context, handlers, check_addr)

            yield (0, (name, sysctl.oid_number, sysctl.get_perms(), format_hints.Hex(check_addr), val, module_name,
                       symbol_name))

    def run(self):
        return renderers.TreeGrid([("Name", str), ("Number", int), ("Perms", str),
                                   ("Handler Address", format_hints.Hex), ("Value", str), ("Handler Module", str),
                                   ("Handler Symbol", str)], self._generator())
