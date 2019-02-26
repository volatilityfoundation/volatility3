# This file was contributed to the Volatility Framework Version 3.
# Copyright (C) 2018 Volatility Foundation.
#
# THE LICENSED WORK IS PROVIDED UNDER THE TERMS OF THE Volatility Contributors
# Public License V1.0("LICENSE") AS FIRST COMPLETED BY: Volatility Foundation,
# Inc. ANY USE, PUBLIC DISPLAY, PUBLIC PERFORMANCE, REPRODUCTION OR DISTRIBUTION
# OF, OR PREPARATION OF SUBSEQUENT WORKS, DERIVATIVE WORKS OR DERIVED WORKS BASED
# ON, THE LICENSED WORK CONSTITUTES RECIPIENT'S ACCEPTANCE OF THIS LICENSE AND ITS
# TERMS, WHETHER OR NOT SUCH RECIPIENT READS THE TERMS OF THE LICENSE. "LICENSED
# WORK,” “RECIPIENT" AND “DISTRIBUTOR" ARE DEFINED IN THE LICENSE. A COPY OF THE
# LICENSE IS LOCATED IN THE TEXT FILE ENTITLED "LICENSE.txt" ACCOMPANYING THE
# CONTENTS OF THIS FILE. IF A COPY OF THE LICENSE DOES NOT ACCOMPANY THIS FILE, A
# COPY OF THE LICENSE MAY ALSO BE OBTAINED AT THE FOLLOWING WEB SITE:
# https://www.volatilityfoundation.org/license/vcpl_v1.0
#
# Software distributed under the License is distributed on an "AS IS" basis,
# WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License for the
# specific language governing rights and limitations under the License.
#

from typing import Generator, Iterable, Optional, Set, Tuple

from volatility.framework import constants, objects
from volatility.framework import exceptions, interfaces
from volatility.framework.objects import utility
from volatility.framework.renderers import conversion
from volatility.framework.symbols import generic


class proc(generic.GenericIntelProcess):

    def get_task(self):
        return self.task.dereference().cast("task")

    def add_process_layer(self, config_prefix: str = None, preferred_name: str = None) -> Optional[str]:
        """Constructs a new layer based on the process's DTB.
        Returns the name of the Layer or None.
        """
        parent_layer = self._context.memory[self.vol.layer_name]

        if not isinstance(parent_layer, interfaces.layers.TranslationLayerInterface):
            raise TypeError("Parent layer is not a translation layer, unable to construct process layer")

        try:
            dtb = self.get_task().map.pmap.pm_cr3
        except exceptions.PagedInvalidAddressException:
            return None

        # Add the constructed layer and return the name
        return self._add_process_layer(self._context, dtb, config_prefix, preferred_name)

    def get_map_iter(self) -> Iterable[interfaces.objects.ObjectInterface]:
        try:
            task = self.get_task()
        except exceptions.PagedInvalidAddressException:
            return

        try:
            current_map = task.map.hdr.links.next
        except exceptions.PagedInvalidAddressException:
            return

        seen = set()  # type: Set[int]

        for i in range(task.map.hdr.nentries):
            if not current_map or current_map.vol.offset in seen:
                break

            yield current_map
            seen.add(current_map.vol.offset)
            current_map = current_map.links.next

    ######
    # ikelos: this breaks with multi threading on, but works with it disabled
    # with multi threading on, it throws that same error about v4 pickle stuff that linux originally did
    # the fix for linux was to call int() so that we were not returning vol objects.
    # I call int() on these and the code works nearly 1-1 with the linux one so I am very confused
    ######
    def get_process_memory_sections(self,
                                    context: interfaces.context.ContextInterface,
                                    config_prefix: str,
                                    rw_no_file: bool = False) -> \
            Generator[Tuple[int, int], None, None]:
        """Returns a list of sections based on the memory manager's view of this task's virtual memory"""
        for vma in self.get_map_iter():
            start = int(vma.links.start)
            end = int(vma.links.end)

            if rw_no_file:
                if vma.get_perms() != "rw" or vma.get_path(context, config_prefix) != "":
                    if vma.get_special_path() != "[heap]":
                        continue

            yield (start, end - start)


class fileglob(objects.Struct):

    def get_fg_type(self):
        ret = "INVALID"
        if self.has_member("fg_type"):
            ret = self.member(attr = 'fg_type')
        elif self.fg_ops != 0:
            try:
                ret = self.fg_ops.fo_type
            except exceptions.PagedInvalidAddressException:
                pass

        return ret.description


class vm_map_object(objects.Struct):

    def get_map_object(self):
        if self.has_member("vm_object"):
            return self.vm_object
        elif self.has_member("vmo_object"):
            return self.vmo_object

        raise AttributeError("vm_map_object -> get_object")


class vnode(objects.Struct):

    def _do_calc_path(self, ret, vnodeobj, vname):
        if vnodeobj is None:
            return

        if vname:
            ret.append(utility.pointer_to_string(vname, 255))

        if int(vnodeobj.v_flag) & 0x000001 != 0 and int(vnodeobj.v_mount) != 0:
            if int(vnodeobj.v_mount.mnt_vnodecovered) != 0:
                self._do_calc_path(ret, vnodeobj.v_mount.mnt_vnodecovered, vnodeobj.v_mount.mnt_vnodecovered.v_name)
        else:
            self._do_calc_path(ret, vnodeobj.v_parent, vnodeobj.v_parent.v_name)

    def full_path(self):
        if self.v_flag & 0x000001 != 0 and self.v_mount != 0 and self.v_mount.mnt_flag & 0x00004000 != 0:
            ret = b"/"
        else:
            elements = []
            files = []

            self._do_calc_path(elements, self, self.v_name)
            elements.reverse()

            for e in elements:
                files.append(e.encode("utf-8"))

            ret = b"/".join(files)
            if ret:
                ret = b"/" + ret

        return ret.decode("utf-8")


class vm_map_entry(objects.Struct):

    def is_suspicious(self, context, config_prefix):
        """Flags memory regions that are mapped rwx or that map an executable not back from a file on disk"""
        ret = False

        perms = self.get_perms()

        if perms == "rwx":
            ret = True

        elif perms == "r-x" and self.get_path(context, config_prefix) == "":
            ret = True

        return ret

    def get_perms(self):
        permask = "rwx"
        perms = ""

        for (ctr, i) in enumerate([1, 3, 5]):
            if (self.protection & i) == i:
                perms = perms + permask[ctr]
            else:
                perms = perms + "-"

        return perms

    def get_range_alias(self):
        if self.has_member("alias"):
            ret = int(self.alias)
        else:
            ret = int(self.vme_offset) & 0xfff

        return ret

    def get_special_path(self):
        check = self.get_range_alias()

        if 0 < check < 10:
            ret = "[heap]"
        elif check == 30:
            ret = "[stack]"
        else:
            ret = ""

        return ret

    def get_path(self, context, config_prefix):
        node = self.get_vnode(context, config_prefix)

        if type(node) == str and node == "sub_map":
            ret = node
        elif node:
            path = []
            while node:
                v_name = utility.pointer_to_string(node.v_name, 255)
                path.append(v_name)
                node = node.v_parent
            path.reverse()
            ret = "/" + "/".join(path)
        else:
            ret = ""

        return ret

    def get_object(self):
        if self.has_member("vme_object"):
            return self.vme_object
        elif self.has_member("object"):
            return self.object

        raise AttributeError("vm_map_entry -> get_object: Unable to determine object")

    def get_offset(self):
        if self.has_member("vme_offset"):
            return self.vme_offset
        elif self.has_member("offset"):
            return self.offset

        raise AttributeError("vm_map_entry -> get_offset: Unable to determine offset")

    def get_vnode(self, context, config_prefix):
        if self.is_sub_map == 1:
            return "sub_map"

        # based on find_vnode_object
        vnode_object = self.get_object().get_map_object()

        found_end = False

        while not found_end:
            try:
                tmp_vnode_object = vnode_object.shadow.dereference()
            except exceptions.PagedInvalidAddressException:
                break

            if tmp_vnode_object.vol.offset == 0:
                found_end = True
            else:
                vnode_object = tmp_vnode_object

        try:
            ops = vnode_object.pager.mo_pager_ops.dereference()
        except exceptions.PagedInvalidAddressException:
            return None

        found = False
        for sym in context.symbol_space.get_symbols_by_location(ops.vol.offset):
            if sym.split(constants.BANG)[1] in ["vnode_pager_ops", "_vnode_pager_ops"]:
                found = True
                break

        if found:
            vpager = context.object(
                config_prefix + constants.BANG + "vnode_pager",
                layer_name = vnode_object.vol.layer_name,
                offset = vnode_object.pager)
            ret = vpager.vnode_handle
        else:
            ret = None

        return ret


class socket(objects.Struct):

    def get_inpcb(self):
        try:
            ret = self.so_pcb.dereference().cast("inpcb")
        except exceptions.PagedInvalidAddressException:
            ret = None

        return ret

    def get_family(self):
        return self.so_proto.pr_domain.dom_family

    def get_protocol_as_string(self):
        proto = self.so_proto.pr_protocol

        if proto == 6:
            ret = "TCP"
        elif proto == 17:
            ret = "UDP"
        else:
            ret = ""

        return ret

    def get_state(self):
        ret = ""

        if self.so_proto.pr_protocol == 6:
            inpcb = self.get_inpcb()
            if inpcb is not None:
                ret = inpcb.get_tcp_state()

        return ret

    def get_connection_info(self):
        inpcb = self.get_inpcb()

        if inpcb is None:
            ret = None
        elif self.get_family() == 2:
            ret = inpcb.get_ipv4_info()
        else:
            ret = inpcb.get_ipv6_info()

        return ret

    def get_converted_connection_info(self):
        vals = self.get_connection_info()

        if vals:
            ret = conversion.convert_network_four_tuple(self.get_family(), vals)
        else:
            ret = None

        return ret


class inpcb(objects.Struct):

    def get_tcp_state(self):
        tcp_states = ("CLOSED", "LISTEN", "SYN_SENT", "SYN_RECV", "ESTABLISHED", "CLOSE_WAIT", "FIN_WAIT1", "CLOSING",
                      "LAST_ACK", "FIN_WAIT2", "TIME_WAIT")

        try:
            tcpcb = self.inp_ppcb.dereference().cast("tcpcb")
        except exceptions.PagedInvalidAddressException:
            return ""

        state_type = tcpcb.t_state
        if state_type and state_type < len(tcp_states):
            state = tcp_states[state_type]
        else:
            state = ""

        return state

    def get_ipv4_info(self):
        lip = self.inp_dependladdr.inp46_local.ia46_addr4.s_addr
        lport = self.inp_lport

        rip = self.inp_dependfaddr.inp46_foreign.ia46_addr4.s_addr
        rport = self.inp_fport

        return [lip, lport, rip, rport]

    def get_ipv6_info(self):
        lip = self.inp_dependladdr.inp6_local.member(attr = '__u6_addr').member(attr = '__u6_addr32')
        lport = self.inp_lport

        rip = self.inp_dependfaddr.inp6_foreign.member(attr = '__u6_addr').member(attr = '__u6_addr32')
        rport = self.inp_fport

        return [lip, lport, rip, rport]
