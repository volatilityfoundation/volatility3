# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
import logging
from typing import List

import volatility
from volatility.framework import exceptions, interfaces
from volatility.framework import renderers, constants, contexts
from volatility.framework.automagic import mac
from volatility.framework.configuration import requirements
from volatility.framework.interfaces import plugins
from volatility.framework.renderers import format_hints
from volatility.framework.objects import utility

vollog = logging.getLogger(__name__)


class Check_sysctl(plugins.PluginInterface):
    """Check sysctl handlers for hooks."""

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.TranslationLayerRequirement(name = 'primary',
                                                     description = 'Memory layer for the kernel',
                                                     architectures = ["Intel32", "Intel64"]),
            requirements.SymbolTableRequirement(name = "darwin", description = "Mac kernel symbols")
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
                var_array = kernel.object(object_type = var_name)
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
            except exceptions.PagedInvalidAddressException:
                return

        while sysctl:
            try:
                name = utility.pointer_to_string(sysctl.oid_name, 128)
            except exceptions.PagedInvalidAddressException:
                name = ""

            if len(name) == 0:
                break

            ctltype = sysctl.get_ctltype()

            try:
                arg1_ptr = sysctl.oid_arg1.dereference().vol.offset
            except exceptions.InvalidPagedAddressException:
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
                except exceptions.PagedInvalidAddressException:
                    val = "-1"

            elif ctltype == 'CTLTYPE_STRING':
                try:
                    val = utility.pointer_to_string(sysctl.oid_arg1, 64)
                except exceptions.PagedInvalidAddressException:
                    val = ""
            else:
                val = ctltype

            yield (sysctl, name, val)

            try:
                sysctl = sysctl.oid_link.sle_next
            except exceptions.PagedInvalidAddressException:
                break

    def _generator(self):
        mac.MacUtilities.aslr_mask_symbol_table(self.context, self.config['darwin'], self.config['primary'])

        kernel = contexts.Module(self._context, self.config['darwin'], self.config['primary'], 0)

        sysctl_list = kernel.object_from_symbol(symbol_name = "sysctl__children")

        for sysctl, name, val in self._process_sysctl_list(kernel, sysctl_list):
            check_addr = sysctl.oid_handler

            if check_addr == 0:
                sym_name = "<No Handler>"
            else:
                symbols = list(self.context.symbol_space.get_symbols_by_location(check_addr))

                if len(symbols) > 0:
                    sym_name = str(symbols[0].split(constants.BANG)[1]) if constants.BANG in symbols[0] else \
                        str(symbols[0])
                else:
                    sym_name = "UNKNOWN"

            yield (0, (name, sysctl.oid_number, sysctl.get_perms(), format_hints.Hex(check_addr), val, sym_name))

    def run(self):
        return renderers.TreeGrid([("Name", str), ("Number", int), ("Perms", str),
                                   ("Handler Address", format_hints.Hex), ("Value", str), ("Handler Symbol", str)],
                                  self._generator())
