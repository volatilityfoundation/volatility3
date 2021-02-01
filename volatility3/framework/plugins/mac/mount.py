# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
"""A module containing a collection of plugins that produce data typically
found in Mac's mount command."""
from volatility3.framework import renderers, interfaces, contexts
from volatility3.framework.configuration import requirements
from volatility3.framework.interfaces import plugins
from volatility3.framework.objects import utility
from volatility3.framework.symbols import mac


class Mount(plugins.PluginInterface):
    """A module containing a collection of plugins that produce data typically
    foundin Mac's mount command"""

    _required_framework_version = (1, 0, 0)

    _version = (1, 0, 0)

    @classmethod
    def get_requirements(cls):
        return [
            requirements.TranslationLayerRequirement(name = 'primary',
                                                     description = 'Memory layer for the kernel',
                                                     architectures = ["Intel32", "Intel64"]),
            requirements.VersionRequirement(name = 'macutils', component = mac.MacUtilities, version = (1, 0, 0)),
            requirements.SymbolTableRequirement(name = "darwin", description = "Mac kernel symbols")
        ]

    @classmethod
    def list_mounts(cls, context: interfaces.context.ContextInterface, layer_name: str, darwin_symbols: str):
        """Lists all the mount structures in the primary layer.

        Args:
            context: The context to retrieve required elements (layers, symbol tables) from
            layer_name: The name of the layer on which to operate
            darwin_symbols: The name of the table containing the kernel symbols

        Returns:
            A list of mount structures from the `layer_name` layer
        """
        kernel = contexts.Module(context, darwin_symbols, layer_name, 0)

        list_head = kernel.object_from_symbol(symbol_name = "mountlist")

        for mount in mac.MacUtilities.walk_tailq(list_head, "mnt_list"):
            yield mount

    def _generator(self):
        for mount in self.list_mounts(self.context, self.config['primary'], self.config['darwin']):
            vfs = mount.mnt_vfsstat
            device_name = utility.array_to_string(vfs.f_mntonname)
            mount_point = utility.array_to_string(vfs.f_mntfromname)
            mount_type = utility.array_to_string(vfs.f_fstypename)

            yield 0, (device_name, mount_point, mount_type)

    def run(self):
        return renderers.TreeGrid([("Device", str), ("Mount Point", str), ("Type", str)], self._generator())
