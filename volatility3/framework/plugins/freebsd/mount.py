# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
"""A module containing a collection of plugins that produce data typically
found in Freebsd's mount command."""

from typing import List

from volatility3.framework import renderers, interfaces
from volatility3.framework.configuration import requirements
from volatility3.framework.interfaces import plugins
from volatility3.framework.objects import utility
from volatility3.framework.renderers import format_hints


class Mount(plugins.PluginInterface):
    """Lists mounted file systems."""

    _required_framework_version = (2, 0, 0)

    _version = (1, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(
                name = "kernel",
                description = "Kernel module for the OS",
                architectures = ["Intel32", "Intel64"],
            ),
        ]

    @classmethod
    def list_mounts(cls, context: interfaces.context.ContextInterface, kernel_module_name: str):
        """Lists all the mounted file systems in the primary layer.

        Args:
            context: The context to retrieve required elements (layers, symbol tables) from
            kernel_module_name: The name of the the kernel module on which to operate

        Yields:
            Mounted file systems
        """
        kernel = context.modules[kernel_module_name]
        kernel_layer = context.layers[kernel.layer_name]

        mountlist = kernel.object_from_symbol(symbol_name = "mountlist")
        mount = mountlist.tqh_first

        while mount != 0:
            yield mount.dereference()
            mount = mount.mnt_list.tqe_next

    def _generator(self):
        for mount in self.list_mounts(self.context, self.config["kernel"]):
            mount_mntfromname = utility.array_to_string(mount.mnt_stat.f_mntfromname)
            mount_mntonname = utility.array_to_string(mount.mnt_stat.f_mntonname)
            mount_fstypename = utility.array_to_string(mount.mnt_stat.f_fstypename)

            yield 0, (format_hints.Hex(mount.vol.offset), mount_mntfromname, mount_mntonname, mount_fstypename)

    def run(self):
        return renderers.TreeGrid(
            [("Offset", format_hints.Hex), ("Special device", str), ("Mount point", str), ("Type", str)],
            self._generator(),
        )
