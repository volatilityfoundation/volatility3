# This file is Copyright 2020 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
import logging

from typing import Iterable

from volatility.framework import renderers, interfaces, exceptions
from volatility.framework.objects import utility
from volatility.framework.configuration import requirements
from volatility.framework.interfaces import plugins
from volatility.framework.renderers import format_hints
from volatility.framework.symbols import mac
from volatility.plugins.mac import mount

vollog = logging.getLogger(__name__)

import sys

def cprint(msg):
    return
    print("")
    sys.stdout.flush()
    print("grepme: %s" % msg)
    sys.stdout.flush()

def dprint(msg):
    if 0:
        print("")
        sys.stdout.flush()
        print("grepme: %s" % msg)
        sys.stdout.flush()

class List_Files(plugins.PluginInterface):
    """Lists all open file descriptors for all processes."""

    @classmethod
    def get_requirements(cls):
        return [
            requirements.TranslationLayerRequirement(name = 'primary',
                                                     description = 'Kernel Address Space',
                                                     architectures = ["Intel32", "Intel64"]),
            requirements.SymbolTableRequirement(name = "darwin", description = "Mac Kernel"),
            requirements.PluginRequirement(name = 'mount', plugin = mount.Mount, version = (1, 0, 0)),
    ]

    @classmethod
    def _vnode_name(cls, vnode):
        # roots of mount points have special name handling
        if vnode.v_flag & 1 == 1:
            v_name = vnode.full_path()
            print("found root mount at %x" % vnode.dereference().vol.offset)
        else:
            try:
                v_name = utility.pointer_to_string(vnode.dereference().v_name, 255)
            except exceptions.InvalidAddressException:
                v_name = None

        return v_name

    @classmethod
    def _get_parent(cls, vnode):
        parent = None

        # root entries do not have parents
        # and parents of normal files can be smeared
        try:
            parent = vnode.v_parent
        except exceptions.InvalidAddressException:
            pass

        return parent

    @classmethod
    def _add_vnode(cls, vnode, loop_vnodes):
        key = vnode.dereference().vol.offset
        added = False

        if not key in loop_vnodes:
            # We can't do anything with a no-name vnode
            v_name = cls._vnode_name(vnode)
            if v_name == None:
                return added

            parent = cls._get_parent(vnode)
            if parent:
                parent_val = parent.dereference().vol.offset
            else:
                parent_val = None
        
            loop_vnodes[key] = (v_name, parent_val, vnode)

            added = True

        return added

    @classmethod
    def _walk_vnode(cls, vnode, loop_vnodes):
        while vnode:
            if not cls._add_vnode(vnode, loop_vnodes):
                break

            parent = cls._get_parent(vnode)
            while parent:
                cls._walk_vnode(parent, loop_vnodes)
                parent = cls._get_parent(parent)

            try:
                vnode = vnode.v_mntvnodes.tqe_next
            except exceptions.InvalidAddressException:
                break

    @classmethod
    def _process_vnode(cls, vnode, loop_vnodes):
        cls._walk_vnode(vnode, loop_vnodes)
   
    @classmethod
    def _walk_vnodelist(cls, list_head, loop_vnodes):
        for vnode in mac.MacUtilities.walk_tailq(list_head,  "v_mntvnodes"):
            cls._process_vnode(vnode, loop_vnodes)

    @classmethod
    def _walk_mounts(cls,
                   context: interfaces.context.ContextInterface,
                   layer_name: str,
                   darwin_symbols: str) -> \
            Iterable[interfaces.objects.ObjectInterface]:
        
        loop_vnodes = {}

        # iterate each vnode source from each mount
        list_mounts = mount.Mount.list_mounts(context, layer_name, darwin_symbols)
        for mnt in list_mounts:
            cls._walk_vnodelist(mnt.mnt_vnodelist,   loop_vnodes)
            cls._walk_vnodelist(mnt.mnt_workerqueue, loop_vnodes)
            cls._walk_vnodelist(mnt.mnt_newvnodes,   loop_vnodes)

            cls._process_vnode(mnt.mnt_vnodecovered, loop_vnodes)
            cls._process_vnode(mnt.mnt_realrootvp, loop_vnodes)
            cls._process_vnode(mnt.mnt_devvp, loop_vnodes)
           
        return loop_vnodes

    @classmethod
    def _build_path(cls, vnodes, vnode_name, parent_offset):
        path = [vnode_name]
        
        while parent_offset in vnodes:
            parent_name, parent_offset, _ = vnodes[parent_offset]
            if parent_offset == None:
                parent_offset = 0
            
            path.insert(0, parent_name)

        if len(path) > 1:
            path = "/".join(path)
        else:
            path = vnode_name

        return path
    
    @classmethod
    def list_files(cls,
                   context: interfaces.context.ContextInterface,
                   layer_name: str,
                   darwin_symbols: str) -> \
            Iterable[interfaces.objects.ObjectInterface]:

        vnodes = cls._walk_mounts(context, layer_name, darwin_symbols)

        dprint("got %d vnodes" % len(vnodes))

        for voff, (vnode_name, parent_offset, vnode) in vnodes.items():
            full_path = cls._build_path(vnodes, vnode_name, parent_offset)
       
            yield vnode, full_path

    def _generator(self):
        for vnode, full_path in self.list_files(self.context,
                                           self.config['primary'],
                                           self.config['darwin']):

            yield (0, (format_hints.Hex(vnode.dereference().vol.offset), full_path))

    def run(self):
        return renderers.TreeGrid([("Address", format_hints.Hex), ("File Path", str)],
                                  self._generator())
