# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl_v1.0
#

from volatility.framework import exceptions, renderers, interfaces, contexts
from volatility.framework.automagic import mac
from volatility.framework.configuration import requirements
from volatility.framework.interfaces import plugins
from volatility.framework.objects import utility
from volatility.framework.renderers import format_hints

import volatility.plugins.mac.common as mac_common

class Ifconfig(plugins.PluginInterface):
    """Lists loaded kernel modules"""

    _version = (1, 0, 0)

    @classmethod
    def get_requirements(cls):
        return [
            requirements.TranslationLayerRequirement(
                name = 'primary', description = 'Memory layer for the kernel', architectures = ["Intel32", "Intel64"]),
            requirements.SymbolTableRequirement(name = "darwin", description = "Linux kernel symbols")
        ]

    def _generator(self):
        mac.MacUtilities.aslr_mask_symbol_table(self.context, self.config['darwin'], self.config['primary'])

        kernel = contexts.Module(self._context, self.config['darwin'], self.config['primary'], 0)

        try:
            list_head = kernel.object_from_symbol(symbol_name = "ifnet_head")
        except exceptions.SymbolError:
            list_head = kernel.object_from_symbol(symbol_name = "dlil_ifnet_head")

        for ifnet in mac_common.walk_tailq(list_head, "if_link"):
            name = utility.pointer_to_string(ifnet.if_name, 32)
            unit = ifnet.if_unit
            if ifnet.if_flags & 0x100 == 0x100: # IFF_PROMISC
                prom = "True"
            else:
                prom = "False"

            sock_addr_dl = ifnet.sockaddr_dl()
            if sock_addr_dl is None:
                mac_addr = renderers.UnreadableValue() 
            else:
                mac_addr = str(sock_addr_dl)

            for ifaddr in mac_common.walk_tailq(ifnet.if_addrhead, "ifa_link"):
                ip = ifaddr.ifa_addr.get_address()

                yield (0, ("{0}{1}".format(name, unit), ip, mac_addr, prom))

    def run(self):
        return renderers.TreeGrid([("Interface", str), ("IP Address", str), ("Mac Address", str), ("Promiscuous", str)], self._generator())




