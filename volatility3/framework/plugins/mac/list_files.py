# This file is Copyright 2020 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
import logging
from typing import Iterable, Optional

from volatility3.framework import renderers, interfaces, exceptions
from volatility3.framework.configuration import requirements
from volatility3.framework.interfaces import plugins
from volatility3.framework.objects import utility
from volatility3.framework.renderers import format_hints
from volatility3.framework.symbols import mac
from volatility3.plugins.mac import mount

vollog = logging.getLogger(__name__)


class List_Files(plugins.PluginInterface):
    """Lists all open file descriptors for all processes."""

    _required_framework_version = (2, 0, 0)

    @classmethod
    def get_requirements(cls):
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Kernel module for the OS",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.PluginRequirement(
                name="mount", plugin=mount.Mount, version=(2, 0, 0)
            ),
        ]

    @classmethod
    def _vnode_name(cls, vnode: interfaces.objects.ObjectInterface) -> Optional[str]:
        # roots of mount points have special name handling
        if vnode.v_flag & 1 == 1:
            v_name = vnode.full_path()
        else:
            try:
                v_name = utility.pointer_to_string(vnode.v_name, 255)
            except exceptions.InvalidAddressException:
                v_name = None

        return v_name

    @classmethod
    def _get_parent(cls, context, vnode):
        # root entries do not have parents
        # and parents of normal files can be smeared
        try:
            parent = vnode.v_parent.dereference()
        except exceptions.InvalidAddressException:
            return None

        if parent and not context.layers[vnode.vol.native_layer_name].is_valid(
            parent.vol.offset, parent.vol.size
        ):
            return None

        return parent

    @classmethod
    def _add_vnode(cls, context, vnode, loop_vnodes):
        """
        Adds the given vnode to loop_vnodes.

        loop_vnodes is key off the address of a vnode
        and holds its name, parent address, and object
        """

        if not context.layers[vnode.vol.native_layer_name].is_valid(
            vnode.vol.offset, vnode.vol.size
        ):
            return False

        key = vnode.vol.offset
        added = False

        if key not in loop_vnodes:
            # We can't do anything with a no-name vnode
            v_name = cls._vnode_name(vnode)
            if v_name is None:
                return added

            parent = cls._get_parent(context, vnode)
            if parent:
                parent_val = parent.vol.offset
            else:
                parent_val = None

            loop_vnodes[key] = (v_name, parent_val, vnode)

            added = True

        return added

    @classmethod
    def _walk_vnode(
        cls, context, vnode, loop_vnodes, to_explore: list, visited_vnodes: set
    ):
        """
        Iterates over the list of vnodes associated with the given one.
        Also traverses the parent chain for the vnode and adds each one.
        """

        while vnode:
            if vnode in loop_vnodes or vnode in visited_vnodes:
                return to_explore

            visited_vnodes.add(vnode)

            if not cls._add_vnode(context, vnode, loop_vnodes):
                break

            parent = cls._get_parent(context, vnode)
            if parent not in to_explore:
                to_explore.append(parent)

            try:
                vnode = vnode.v_mntvnodes.tqe_next.dereference()
            except exceptions.InvalidAddressException:
                break

        return to_explore

    @classmethod
    def _walk_vnode_iterative(cls, context, vnode, loop_vnodes, visited_vnodes):
        to_explore = [vnode]
        while to_explore:
            vnode = to_explore.pop(-1)
            to_explore = cls._walk_vnode(
                context, vnode, loop_vnodes, to_explore, visited_vnodes
            )

    @classmethod
    def _walk_vnodelist(cls, context, list_head, loop_vnodes, visited_vnodes):
        for vnode in mac.MacUtilities.walk_tailq(list_head, "v_mntvnodes"):
            cls._walk_vnode_iterative(context, vnode, loop_vnodes, visited_vnodes)

    @classmethod
    def _walk_mounts(
        cls, context: interfaces.context.ContextInterface, kernel_module_name: str
    ) -> Iterable[interfaces.objects.ObjectInterface]:
        loop_vnodes = {}
        visited_vnodes = set()

        # iterate each vnode source from each mount
        list_mounts = mount.Mount.list_mounts(context, kernel_module_name)
        for mnt in list_mounts:
            cls._walk_vnodelist(context, mnt.mnt_vnodelist, loop_vnodes, visited_vnodes)
            cls._walk_vnodelist(
                context, mnt.mnt_workerqueue, loop_vnodes, visited_vnodes
            )
            cls._walk_vnodelist(context, mnt.mnt_newvnodes, loop_vnodes, visited_vnodes)
            cls._walk_vnode_iterative(
                context, mnt.mnt_vnodecovered, loop_vnodes, visited_vnodes
            )
            cls._walk_vnode_iterative(
                context, mnt.mnt_realrootvp, loop_vnodes, visited_vnodes
            )
            cls._walk_vnode_iterative(
                context, mnt.mnt_devvp, loop_vnodes, visited_vnodes
            )

        return loop_vnodes

    @classmethod
    def _build_path(cls, vnodes, vnode_name, parent_offset):
        path = [vnode_name]
        seen_offsets = set()

        while parent_offset in vnodes:
            parent_name, parent_offset, _ = vnodes[parent_offset]
            if parent_offset is None:
                parent_offset = 0

            # circular references from smear
            elif parent_offset in seen_offsets:
                path = []
                break

            else:
                seen_offsets.add(parent_offset)

            path.insert(0, parent_name)

        if len(path) > 1:
            path = "/".join(path)
        else:
            path = vnode_name

        if path.startswith("//"):
            path = path[1:]

        return path

    @classmethod
    def list_files(
        cls, context: interfaces.context.ContextInterface, kernel_module_name: str
    ) -> Iterable[interfaces.objects.ObjectInterface]:
        vnodes = cls._walk_mounts(context, kernel_module_name)

        for voff, (vnode_name, parent_offset, vnode) in vnodes.items():
            full_path = cls._build_path(vnodes, vnode_name, parent_offset)

            yield vnode, full_path

    def _generator(self):
        for vnode, full_path in self.list_files(self.context, self.config["kernel"]):
            yield (0, (format_hints.Hex(vnode.vol.offset), full_path))

    def run(self):
        return renderers.TreeGrid(
            [("Address", format_hints.Hex), ("File Path", str)], self._generator()
        )
