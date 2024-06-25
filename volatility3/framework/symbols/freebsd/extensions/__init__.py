# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

import logging
from typing import Iterable, Optional

from volatility3.framework import interfaces, objects
from volatility3.framework.symbols import generic

vollog = logging.getLogger(__name__)


class proc(generic.GenericIntelProcess):

    def add_process_layer(self, config_prefix: str = None, preferred_name: str = None) -> Optional[str]:
        """Constructs a new layer based on the process's DTB.

        Returns the name of the Layer or None.
        """
        parent_layer = self._context.layers[self.vol.layer_name]

        if not isinstance(parent_layer, interfaces.layers.TranslationLayerInterface):
            raise TypeError("Parent layer is not a translation layer, unable to construct process layer")

        dtb = None
        pmap = self.p_vmspace.vm_pmap
        # Freebsd amd64
        if pmap.has_member("pm_ucr3") and pmap.pm_ucr3 != 0xffffffffffffffff:
            dtb = pmap.pm_ucr3
        elif pmap.has_member("pm_cr3"):
            dtb = pmap.pm_cr3
        # Freebsd i386
        elif pmap.has_member("pm_pdir"):
            dtb, _ = parent_layer.translate(pmap.pm_pdir)
        # Freebsd i386 with PAE
        elif pmap.has_member("pm_pdpt"):
            dtb, _ = parent_layer.translate(pmap.pm_pdpt)
        # Freebsd i386 after merge of PAE and non-PAE pmaps into same kernel
        elif pmap.has_member("pm_pdpt_pae") and pmap.pm_pdpt_pae:
            dtb, _ = parent_layer.translate(pmap.pm_pdpt_pae)
        elif pmap.has_member("pm_pdir_nopae") and pmap.pm_pdir_nopae:
            dtb, _ = parent_layer.translate(pmap.pm_pdir_nopae)

        if not dtb:
            return None

        if preferred_name is None:
            preferred_name = self.vol.layer_name + f"_Process{self.p_pid}"

        # Add the constructed layer and return the name
        return self._add_process_layer(self._context, dtb, config_prefix, preferred_name)

    def get_map_iter(self) -> Iterable[interfaces.objects.ObjectInterface]:
        if self.p_vmspace.vm_map.header.has_member("next"):
            current_map = self.p_vmspace.vm_map.header.next
        else:
            current_map = self.p_vmspace.vm_map.header.right

        seen = set()  # type: Set[int]

        for i in range(self.p_vmspace.vm_map.nentries):
            if not current_map or current_map.vol.offset in seen:
                break

            if current_map.eflags & 0x2 == 0:
                # Skip MAP_ENTRY_IS_SUB_MAP
                yield current_map
            seen.add(current_map.vol.offset)
            if current_map.has_member("next"):
                current_map = current_map.next
            else:
                after = current_map.right
                if after.left.start > current_map.start:
                    while True:
                        after = after.left
                        if after.left == current_map:
                            break
                current_map = after


class vm_map_entry(objects.StructType):

    def get_perms(self):
        permask = "rwx"
        perms = ""

        for (ctr, i) in enumerate([1, 3, 5]):
            if (self.protection & i) == i:
                perms = perms + permask[ctr]
            else:
                perms = perms + "-"

        return perms

    def get_path(self, kernel):
        vm_object = self.object.vm_object

        if vm_object == 0:
            return ''

        while vm_object.backing_object != 0:
            vm_object = vm_object.backing_object

        if vm_object.type != 2:  # OBJT_VNODE
            return ''

        vnode = vm_object.handle.dereference().cast('vnode')
        return vnode.get_vpath(kernel)


class vnode(objects.StructType):

    def get_vpath(self, kernel):
        """Lookup pathname of a vnode in the namecache"""
        rootvnode = kernel.object_from_symbol(symbol_name = "rootvnode").dereference()
        vp = self
        components = list()

        while vp.vol.offset != 0:
            if vp.vol.offset == rootvnode.vol.offset:
                if len(components) == 0:
                    components.insert(0, '/')
                else:
                    components.insert(0, '')
                break

            if vp.v_vflag & 0x1 != 0:
                # VV_ROOT set
                vp = vp.v_mount.mnt_vnodecovered.dereference()
            else:
                ncp = vp.v_cache_dst.tqh_first
                if ncp != 0:
                    ncn = ncp.nc_name.cast("string", max_length = ncp.nc_nlen)
                    components.insert(0, str(ncn))
                    vp = ncp.nc_dvp.dereference()
                else:
                    break

        if components:
            return '/'.join(components)
        else:
            return ''
