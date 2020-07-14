# Volatility

# This file is Copyright 2020 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

"""
@author:       Matt Tressler
@contact:      matthewtressler10@gmail.com
"""

import logging
from typing import List

from volatility.framework import interfaces, renderers, exceptions, constants, contexts
from volatility.framework.automagic import linux
from volatility.framework.configuration import requirements
from volatility.framework.interfaces import plugins
from volatility.framework.layers import intel
from volatility.framework.objects import utility
from volatility.plugins.linux import lsmod
from volatility.framework.renderers import format_hints

vollog = logging.getLogger(__name__)


class check_modules(plugins.PluginInterface):
    """Compares module list to sysfs info, if available"""

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.TranslationLayerRequirement(name='primary',
                                                     description='Memory layer for the kernel',
                                                     architectures=["Intel32", "Intel64"]),
            requirements.SymbolTableRequirement(
                name="vmlinux", description="Linux kernel symbols"),

            requirements.PluginRequirement(
                name='lsmod', plugin=lsmod.Lsmod, version=(1, 0, 0))
        ]

    def get_kset_modules(self, vmlinux):

        try:
            module_kset = vmlinux.object_from_symbol("module_kset")
        except exceptions.SymbolError:
            vollog.error("this command is not supported by this profile")
            return

        if not module_kset:
            vollog.error("this command is not supported by this profile")

        ret = {}

        kobj_off = self.context.symbol_space.get_type(
            self.config['vmlinux'] + constants.BANG + 'module_kobject').relative_child_offset('kobj')

        for kobj in module_kset.list.to_list(vmlinux.name + constants.BANG + "kobject", "entry"):

            mod_kobj = vmlinux.object(
                object_type="module_kobject", offset=kobj.vol.offset - kobj_off)

            mod = mod_kobj.mod

            name = utility.pointer_to_string(kobj.name, 32)
            if kobj.name and kobj.reference_count() > 2:
                ret[name] = mod

        return ret

    def _generator(self):
        vmlinux = contexts.Module(
            self.context, self.config['vmlinux'], self.config['primary'], 0)

        kset_modules = self.get_kset_modules(vmlinux)

        lsmod_modules = set(str(utility.array_to_string(modules.name)) for modules in
                            lsmod.Lsmod.list_modules(self.context,
                                                     self.config['primary'], self.config['vmlinux']))

        for mod_name in set(kset_modules.keys()).difference(lsmod_modules):
            yield(0, (format_hints.Hex(kset_modules[mod_name]), str(mod_name)))

    def run(self):
        return renderers.TreeGrid([("Module Address", format_hints.Hex),
                                   ("Module Name", str)], self._generator())