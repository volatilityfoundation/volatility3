# This file is Copyright 2020 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

import logging
from typing import List

from volatility3.framework import interfaces, renderers, exceptions, constants
from volatility3.framework.configuration import requirements
from volatility3.framework.interfaces import plugins
from volatility3.framework.objects import utility
from volatility3.framework.renderers import format_hints
from volatility3.plugins.linux import lsmod

vollog = logging.getLogger(__name__)


class Check_modules(plugins.PluginInterface):
    """Compares module list to sysfs info, if available"""

    _required_framework_version = (2, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Linux kernel",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.PluginRequirement(
                name="lsmod", plugin=lsmod.Lsmod, version=(2, 0, 0)
            ),
        ]

    @classmethod
    def get_kset_modules(
        cls, context: interfaces.context.ContextInterface, vmlinux_name: str
    ):
        vmlinux = context.modules[vmlinux_name]

        try:
            module_kset = vmlinux.object_from_symbol("module_kset")
        except exceptions.SymbolError:
            module_kset = None

        if not module_kset:
            raise TypeError(
                "This plugin requires the module_kset structure. This structure is not present in the supplied symbol table. This means you are either analyzing an unsupported kernel version or that your symbol table is corrupt."
            )

        ret = {}

        kobj_off = vmlinux.get_type("module_kobject").relative_child_offset("kobj")

        for kobj in module_kset.list.to_list(
            vmlinux.symbol_table_name + constants.BANG + "kobject", "entry"
        ):
            mod_kobj = vmlinux.object(
                object_type="module_kobject",
                offset=kobj.vol.offset - kobj_off,
                absolute=True,
            )

            mod = mod_kobj.mod

            name = utility.pointer_to_string(kobj.name, 32)
            if kobj.name and kobj.reference_count() > 2:
                ret[name] = mod

        return ret

    def _generator(self):
        kset_modules = self.get_kset_modules(self.context, self.config["kernel"])

        lsmod_modules = set(
            str(utility.array_to_string(modules.name))
            for modules in lsmod.Lsmod.list_modules(self.context, self.config["kernel"])
        )

        for mod_name in set(kset_modules.keys()).difference(lsmod_modules):
            yield (0, (format_hints.Hex(kset_modules[mod_name]), str(mod_name)))

    def run(self):
        return renderers.TreeGrid(
            [("Module Address", format_hints.Hex), ("Module Name", str)],
            self._generator(),
        )
