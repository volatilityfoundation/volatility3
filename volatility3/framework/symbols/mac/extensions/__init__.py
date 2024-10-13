# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
import contextlib
import logging
import datetime
from typing import Generator, Iterable, Optional, Set, Tuple

from volatility3.framework import constants, exceptions, interfaces, objects
from volatility3.framework.objects import utility
from volatility3.framework.renderers import conversion
from volatility3.framework.symbols import generic

vollog = logging.getLogger(__name__)


class proc(generic.GenericIntelProcess):
    def get_task(self):
        return self.task.dereference().cast("task")

    def add_process_layer(
        self, config_prefix: str = None, preferred_name: str = None
    ) -> Optional[str]:
        """Constructs a new layer based on the process's DTB.

        Returns the name of the Layer or None.
        """
        parent_layer = self._context.layers[self.vol.layer_name]

        if not isinstance(parent_layer, interfaces.layers.TranslationLayerInterface):
            raise TypeError(
                "Parent layer is not a translation layer, unable to construct process layer"
            )

        try:
            dtb = self.get_task().map.pmap.pm_cr3
        except exceptions.InvalidAddressException:
            # Bail out because we couldn't find the DTB
            return None

        if preferred_name is None:
            preferred_name = self.vol.layer_name + f"_Process{self.p_pid}"

        # Add the constructed layer and return the name
        return self._add_process_layer(
            self._context, dtb, config_prefix, preferred_name
        )

    def get_map_iter(self) -> Iterable[interfaces.objects.ObjectInterface]:
        try:
            task = self.get_task()
            current_map = task.map.hdr.links.next
        except exceptions.InvalidAddressException:
            return None

        seen: Set[int] = set()

        for i in range(task.map.hdr.nentries):
            if (
                not current_map
                or current_map.vol.offset in seen
                or not self._context.layers[task.vol.native_layer_name].is_valid(
                    current_map.dereference().vol.offset,
                    current_map.dereference().vol.size,
                )
            ):
                vollog.log(
                    constants.LOGLEVEL_VVV,
                    "Breaking process maps iteration due to invalid state.",
                )
                break

            # ZP_POISON value used to catch programming errors
            if (
                current_map.links.start == 0xDEADBEEFDEADBEEF
                or current_map.links.end == 0xDEADBEEFDEADBEEF
            ):
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
    def get_process_memory_sections(
        self,
        context: interfaces.context.ContextInterface,
        config_prefix: str,
        rw_no_file: bool = False,
    ) -> Generator[Tuple[int, int], None, None]:
        """Returns a list of sections based on the memory manager's view of
        this task's virtual memory."""
        for vma in self.get_map_iter():
            start = int(vma.links.start)
            end = int(vma.links.end)

            if rw_no_file:
                if (
                    vma.get_perms() != "rw"
                    or vma.get_path(context, config_prefix) != ""
                ):
                    if vma.get_special_path() != "[heap]":
                        continue

            yield (start, end - start)

    def get_pid(self) -> int:
        return self.p_pid

    def get_parent_pid(self) -> int:
        return self.p_ppid

    def get_name(self) -> str:
        return utility.array_to_string(self.p_comm)

    def get_create_time(self) -> datetime.datetime:
        start_time_seconds = self.p_start.tv_sec
        start_time_microseconds = self.p_start.tv_usec
        return datetime.datetime.fromtimestamp(
            start_time_seconds + start_time_microseconds / 1e6, datetime.timezone.utc
        )


class fileglob(objects.StructType):
    def get_fg_type(self):
        ret = None

        if self.has_member("fg_type"):
            ret = self.fg_type
        elif self.fg_ops != 0:
            with contextlib.suppress(exceptions.InvalidAddressException):
                ret = self.fg_ops.fo_type

        if ret:
            ret = str(ret.description).replace("DTYPE_", "")

        return ret


class vm_map_object(objects.StructType):
    def get_map_object(self):
        if self.has_member("vm_object"):
            return self.vm_object
        elif self.has_member("vmo_object"):
            return self.vmo_object

        raise AttributeError("vm_map_object -> get_object")


class vnode(objects.StructType):
    def _do_calc_path(self, ret, vnodeobj, vname):
        if vnodeobj is None:
            return None

        if vname:
            try:
                ret.append(utility.pointer_to_string(vname, 255))
            except exceptions.InvalidAddressException:
                return None

        if int(vnodeobj.v_flag) & 0x000001 != 0 and int(vnodeobj.v_mount) != 0:
            if int(vnodeobj.v_mount.mnt_vnodecovered) != 0:
                self._do_calc_path(
                    ret,
                    vnodeobj.v_mount.mnt_vnodecovered,
                    vnodeobj.v_mount.mnt_vnodecovered.v_name,
                )
        else:
            try:
                parent = vnodeobj.v_parent
                parent_name = parent.v_name
            except exceptions.InvalidAddressException:
                return None

            self._do_calc_path(ret, parent, parent_name)

    def full_path(self):
        if (
            self.v_flag & 0x000001 != 0
            and self.v_mount != 0
            and self.v_mount.mnt_flag & 0x00004000 != 0
        ):
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


class vm_map_entry(objects.StructType):
    def is_suspicious(self, context, config_prefix):
        """Flags memory regions that are mapped rwx or that map an executable
        not back from a file on disk."""
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

        for ctr, i in enumerate([1, 3, 5]):
            if (self.protection & i) == i:
                perms = perms + permask[ctr]
            else:
                perms = perms + "-"

        return perms

    def get_range_alias(self):
        if self.has_member("alias"):
            ret = int(self.alias)
        else:
            ret = int(self.vme_offset) & 0xFFF

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
            seen: Set[int] = set()
            while node and node.vol.offset not in seen:
                try:
                    v_name = utility.pointer_to_string(node.v_name, 255)
                except exceptions.InvalidAddressException:
                    break

                path.append(v_name)
                if len(path) > 1024:
                    break

                seen.add(node.vol.offset)

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
        if vnode_object == 0:
            return None

        found_end = False
        while not found_end:
            try:
                tmp_vnode_object = vnode_object.shadow.dereference()
            except exceptions.InvalidAddressException:
                break

            if tmp_vnode_object.vol.offset == 0:
                found_end = True
            else:
                vnode_object = tmp_vnode_object

        if vnode_object.vol.offset == 0:
            return None

        try:
            pager = vnode_object.pager
            if pager == 0:
                return None

            ops = pager.mo_pager_ops.dereference()
        except exceptions.InvalidAddressException:
            return None

        found = False
        for sym in context.symbol_space.get_symbols_by_location(ops.vol.offset):
            if sym.split(constants.BANG)[1] in ["vnode_pager_ops", "_vnode_pager_ops"]:
                found = True
                break

        if found:
            vpager = context.object(
                config_prefix + constants.BANG + "vnode_pager",
                layer_name=vnode_object.vol.native_layer_name,
                offset=vnode_object.pager,
            )
            ret = vpager.vnode_handle
        else:
            ret = None

        return ret


class socket(objects.StructType):
    def get_inpcb(self):
        try:
            ret = self.so_pcb.dereference().cast("inpcb")
        except exceptions.InvalidAddressException:
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


class inpcb(objects.StructType):
    def get_tcp_state(self):
        tcp_states = (
            "CLOSED",
            "LISTEN",
            "SYN_SENT",
            "SYN_RECV",
            "ESTABLISHED",
            "CLOSE_WAIT",
            "FIN_WAIT1",
            "CLOSING",
            "LAST_ACK",
            "FIN_WAIT2",
            "TIME_WAIT",
        )

        try:
            tcpcb = self.inp_ppcb.dereference().cast("tcpcb")
        except exceptions.InvalidAddressException:
            return ""

        state_type = tcpcb.t_state
        if state_type and state_type < len(tcp_states):
            state = tcp_states[state_type]
        else:
            state = ""

        return state

    def get_ipv4_info(self):
        try:
            lip = self.inp_dependladdr.inp46_local.ia46_addr4.s_addr
        except exceptions.InvalidAddressException:
            return None

        lport = self.inp_lport

        try:
            rip = self.inp_dependfaddr.inp46_foreign.ia46_addr4.s_addr
        except exceptions.InvalidAddressException:
            return None

        rport = self.inp_fport

        return [lip, lport, rip, rport]

    def get_ipv6_info(self):
        try:
            lip = self.inp_dependladdr.inp6_local.member(attr="__u6_addr").member(
                attr="__u6_addr32"
            )
        except exceptions.InvalidAddressException:
            return None

        lport = self.inp_lport

        try:
            rip = self.inp_dependfaddr.inp6_foreign.member(attr="__u6_addr").member(
                attr="__u6_addr32"
            )
        except exceptions.InvalidAddressException:
            return None

        rport = self.inp_fport

        return [lip, lport, rip, rport]


class queue_entry(objects.StructType):
    def walk_list(
        self,
        list_head: interfaces.objects.ObjectInterface,
        member_name: str,
        type_name: str,
        max_size: int = 4096,
    ) -> Iterable[interfaces.objects.ObjectInterface]:
        """
        Walks a queue in a smear-aware and smear-resistant manner

        smear is detected by:
            - the max_size parameter sets an upper bound
            - each seen entry is only allowed once

        attempts to work around smear:
            - the list is walked in both directions to help find as many elements as possible

        Args:
            list_head   - the head of the list
            member_name - the name of the embedded list member
            type_name   - the type of each element in the list
            max_size    - the maximum amount of elements that will be returned

        Returns:
            Each instance of the queue cast as "type_name" type
        """

        yielded = 0

        seen = set()

        for attr in ["next", "prev"]:
            with contextlib.suppress(exceptions.InvalidAddressException):
                queue_element = getattr(self, attr).dereference().cast(type_name)
                while (
                    queue_element is not None
                    and queue_element.vol.offset != list_head.vol.offset
                ):
                    if queue_element.vol.offset in seen:
                        break

                    yield queue_element

                    seen.add(queue_element.vol.offset)

                    yielded = yielded + 1
                    if yielded == max_size:
                        return None

                    queue_element = (
                        getattr(queue_element.member(attr=member_name), attr)
                        .dereference()
                        .cast(type_name)
                    )


class ifnet(objects.StructType):
    def sockaddr_dl(self):
        if self.has_member("if_lladdr"):
            try:
                val = self.if_lladdr.ifa_addr.dereference().cast("sockaddr_dl")
            except exceptions.InvalidAddressException:
                val = None
        else:
            try:
                val = self.if_addrhead.tqh_first.ifa_addr.dereference().cast(
                    "sockaddr_dl"
                )
            except exceptions.InvalidAddressException:
                val = None

        return val


# this is used for MAC addresses
class sockaddr_dl(objects.StructType):
    def __str__(self):
        ret = ""

        if self.sdl_alen > 14:
            return ret

        for i in range(self.sdl_alen):
            try:
                e = self.sdl_data[self.sdl_nlen + i]
            except IndexError:
                break

            e = e.cast("unsigned char")

            ret = ret + f"{e:02X}:"

        if ret and ret[-1] == ":":
            ret = ret[:-1]

        return ret


class sockaddr(objects.StructType):
    def get_address(self):
        ip = ""

        family = self.sa_family
        if family == 2:  # AF_INET
            addr_in = self.cast("sockaddr_in")
            ip = conversion.convert_ipv4(addr_in.sin_addr.s_addr)

        elif family == 30:  # AF_INET6
            addr_in6 = self.cast("sockaddr_in6")
            ip = conversion.convert_ipv6(
                addr_in6.sin6_addr.member(attr="__u6_addr").member(attr="__u6_addr32")
            )

        elif family == 18:  # AF_LINK
            addr_dl = self.cast("sockaddr_dl")
            ip = str(addr_dl)

        return ip


class sysctl_oid(objects.StructType):
    def get_perms(self) -> str:
        """
        Returns the actions allowed on the node

        Args: None

        Returns:
            A combination of:
                R - readable
                W - writeable
                L - self handles locking
        """
        ret = ""

        checks = [0x80000000, 0x40000000, 0x00800000]
        perms = ["R", "W", "L"]

        for i, c in enumerate(checks):
            if c & self.oid_kind:
                ret = ret + perms[i]
            else:
                ret = ret + "-"

        return ret

    def get_ctltype(self) -> str:
        """
        Returns the type of the sysctl node

        Args: None

        Returns:
            One of:
                CTLTYPE_NODE
                CTLTYPE_INT
                CTLTYPE_STRING
                CTLTYPE_QUAD
                CTLTYPE_OPAQUE
                an empty string for nodes not in the above types

        Based on sysctl_sysctl_debug_dump_node
        """
        types = {
            1: "CTLTYPE_NODE",
            2: "CTLTYPE_INT",
            3: "CTLTYPE_STRING",
            4: "CTLTYPE_QUAD",
            5: "CTLTYPE_OPAQUE",
        }

        ctltype = self.oid_kind & 0xF

        if 0 < ctltype < 6:
            ret = types[ctltype]
        else:
            ret = ""

        return ret


class kauth_scope(objects.StructType):
    def get_listeners(self):
        for listener in self.ks_listeners:
            if listener != 0 and listener.kll_callback != 0:
                yield listener
