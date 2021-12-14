# This file is Copyright 2021 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
# Author: Gustavo Moreira

import logging
from typing import Callable

from volatility3.framework import renderers, interfaces, exceptions, constants
from volatility3.framework.configuration import requirements
from volatility3.framework.interfaces import plugins
from volatility3.framework.objects import utility
from volatility3.framework.symbols import linux
from volatility3.plugins.linux import lsof


vollog = logging.getLogger(__name__)

class SockHandlers(interfaces.configuration.VersionableInterface):

    _required_framework_version = (2, 0, 0)

    _version = (1, 0, 0)

    def __init__(self, vmlinux, task):
        self._vmlinux = vmlinux
        self._task = task

        netns_id = task.nsproxy.net_ns.get_inode()
        self._netdevices = self._build_network_devices_map(netns_id)

        self._sock_family_handlers = {
            "AF_UNIX": self._unix_sock,
            "AF_INET": self._inet_sock,
            "AF_INET6": self._inet_sock,
            "AF_NETLINK": self._netlink_sock,
            "AF_VSOCK": self._vsock_sock,
            "AF_PACKET": self._packet_sock,
            "AF_XDP": self._xdp_sock,
            "AF_BLUETOOTH": self._bluetooth_sock,
        }

    def _build_network_devices_map(self, netns_id):
        netdevices_map = {}
        nethead = self._vmlinux.object_from_symbol(symbol_name="net_namespace_list")
        net_symname = self._vmlinux.symbol_table_name + constants.BANG + "net"
        for net in nethead.to_list(net_symname, "list"):
            net_device_symname = self._vmlinux.symbol_table_name + constants.BANG + "net_device"
            for net_dev in net.dev_base_head.to_list(net_device_symname, "dev_list"):
                if net.get_inode() != netns_id:
                    continue
                dev_name = str(utility.array_to_string(net_dev.name))
                netdevices_map[net_dev.ifindex] = dev_name
        return netdevices_map

    def process_sock(self, sock):
        family = sock.family
        extended = {}
        sock_handler = self._sock_family_handlers.get(family)
        if sock_handler:
            try:
                sock_fields = sock_handler(sock, extended)
                return *sock_fields, extended
            except exceptions.SymbolError as e:
                # Cannot finds the *_sock type in the symbols
                vollog.warning("Error processing socket family '%s': %s", family, e)
        else:
            vollog.warning("Unsupported family '%s'", family)

        # Even if the sock family is not supported, or the required types
        # are not present in the symbols, we can still show some general
        # information about the socket that may be helpful.
        saddr_tag = daddr_tag = state = "?"

        sock_stat = saddr_tag, daddr_tag, state

        return sock, sock_stat, extended

    def _unix_sock(self, sock, _extended):
        unix_sock = sock.cast("unix_sock")
        state = unix_sock.state
        saddr = unix_sock.name
        sinode = unix_sock.inode
        if unix_sock.peer != 0:
            peer = unix_sock.peer.dereference().cast("unix_sock")
            daddr = peer.name
            dinode = peer.inode
        else:
            daddr = dinode = ""

        saddr_tag = f"{saddr} {sinode}"
        daddr_tag = f"{daddr} {dinode}"
        sock_stat = saddr_tag, daddr_tag, state
        return unix_sock, sock_stat

    def _inet_sock(self, sock, _extended):
        inet_sock = sock.cast("inet_sock")
        saddr = inet_sock.src_addr
        sport = inet_sock.src_port
        daddr = inet_sock.dst_addr
        dport = inet_sock.dst_port
        state = inet_sock.state

        if inet_sock.family == "AF_INET6":
            saddr = f"[{saddr}]"

        saddr_tag = f"{saddr}:{sport}"
        daddr_tag = f"{daddr}:{dport}"
        sock_stat = saddr_tag, daddr_tag, state
        return inet_sock, sock_stat

    def _netlink_sock(self, sock, _extended):
        netlink_sock = sock.cast("netlink_sock")

        saddr_list = []
        src_portid = f"portid:{netlink_sock.portid}"
        saddr_list.append(src_portid)
        if netlink_sock.groups != 0:
            groups_bitmap = netlink_sock.groups.dereference()
            groups_str = f"groups:0x{groups_bitmap:08x}"
            saddr_list.append(groups_str)

        daddr_list = []
        dst_portid = f"portid:{netlink_sock.dst_portid}"
        daddr_list.append(dst_portid)
        dst_group = f"group:0x{netlink_sock.dst_group:08x}"
        daddr_list.append(dst_group)
        module = netlink_sock.module
        if module and netlink_sock.module.name:
            module_name_str = utility.array_to_string(netlink_sock.module.name)
            module_name = f"lkm:{module_name_str}"
            daddr_list.append(module_name)

        saddr_tag = ",".join(saddr_list)
        daddr_tag = ",".join(daddr_list)
        state = netlink_sock.state

        sock_stat = saddr_tag, daddr_tag, state
        return netlink_sock, sock_stat

    def _vsock_sock(self, sock, _extended):
        vsock_sock = sock.cast("vsock_sock")
        saddr = vsock_sock.local_addr.svm_cid
        sport = vsock_sock.local_addr.svm_port
        daddr = vsock_sock.remote_addr.svm_cid
        dport = vsock_sock.remote_addr.svm_port
        state = ""  # Protocol is always 0

        saddr_tag = f"{saddr}:{sport}"
        daddr_tag = f"{daddr}:{dport}"
        sock_stat = saddr_tag, daddr_tag, state
        return vsock_sock, sock_stat

    def _packet_sock(self, sock, extended):
        packet_sock = sock.cast("packet_sock")
        ifindex = packet_sock.ifindex
        dev_name = self._netdevices.get(ifindex, "") if ifindex > 0 else "ANY"

        if sock.has_member("sk_filter"):
            sock_filter = sock.sk_filter
            self.__update_extra_socket_bpf(sock_filter, extended)

        if sock.has_member("sk_reuseport_cb"):
            sock_reuseport_cb = sock.sk_reuseport_cb
            self.__update_extra_socket_bpf(sock_reuseport_cb, extended)

        saddr_tag = f"{dev_name}"
        daddr_tag = ""
        state = packet_sock.state
        sock_stat = saddr_tag, daddr_tag, state
        return packet_sock, sock_stat

    def __update_extra_socket_bpf(self, sock_filter, extended):
        if not sock_filter:
            return

        extended["bpf_filter_type"] = "cBPF"

        if not sock_filter.has_member("prog"):
            return

        bpfprog = sock_filter.prog
        if not bpfprog:
            return

        BPF_PROG_TYPE_UNSPEC = 0
        if bpfprog.type > BPF_PROG_TYPE_UNSPEC:
            extended["bpf_filter_type"] = "eBPF"
            bpfprog_aux = bpfprog.aux
            if bpfprog_aux:
                extended["bpf_filter_id"] = str(bpfprog_aux.id)
                bpfprog_name = str(utility.array_to_string(bpfprog.aux.name))
                if bpfprog_name:
                    extended["bpf_filter_name"] = bpfprog_name

    def _xdp_sock(self, sock, _extended):
        xdp_sock = sock.cast("xdp_sock")
        device = xdp_sock.dev
        if not device:
            return

        dev_name = utility.array_to_string(device.name)
        saddr_tag = f"{dev_name}"

        bpfprog = device.xdp_prog
        if not bpfprog:
            return

        bpfprog_aux = bpfprog.aux
        if bpfprog_aux:
            bpfprog_id = bpfprog_aux.id
            daddr_tag = f"ebpf_prog_id:{bpfprog_id}"
            bpf_name = utility.array_to_string(bpfprog_aux.name)
            if bpf_name:
                daddr_tag += f",ebpf_prog_name:{bpf_name}"
        else:
            daddr_tag = ""

        # Hallelujah, xdp_sock.state is an enum
        xsk_state = xdp_sock.state.lookup()
        state = xsk_state.replace("XSK_", "")

        sock_stat = saddr_tag, daddr_tag, state
        return xdp_sock, sock_stat

    def _bluetooth_sock(self, sock, _extended):
        bt_sock = sock.cast("bt_sock")

        def bt_addr(addr):
            return ":".join(reversed(["%02x" % x for x in addr.b]))

        saddr_tag = daddr_tag = ""
        if bt_sock.protocol == "HCI":
            pinfo = bt_sock.cast("hci_pinfo")
        elif bt_sock.protocol == "L2CAP":
            pinfo = bt_sock.cast("l2cap_pinfo")
            src_addr = bt_addr(pinfo.chan.src)
            dst_addr = bt_addr(pinfo.chan.dst)
            saddr_tag = f"{src_addr}"
            daddr_tag = f"{dst_addr}"
        elif bt_sock.protocol == "RFCOMM":
            pinfo = bt_sock.cast("rfcomm_pinfo")
            src_addr = bt_addr(pinfo.src)
            dst_addr = bt_addr(pinfo.dst)
            channel = pinfo.channel
            saddr_tag = f"[{src_addr}]:{channel}"
            daddr_tag = f"{dst_addr}"
        else:
            vollog.warning("Unsupported bluetooth protocol '%s'", bt_sock.protocol)

        state = bt_sock.state
        sock_stat = saddr_tag, daddr_tag, state
        return bt_sock, sock_stat

class Sockstat(plugins.PluginInterface):
    """Lists all network connections for all processes."""

    _required_framework_version = (2, 0, 0)

    _version = (1, 0, 0)

    @classmethod
    def get_requirements(cls):
        return [
            requirements.ModuleRequirement(name="kernel", description="Linux kernel",
                                           architectures=["Intel32", "Intel64"]),
            requirements.VersionRequirement(name="SockHandlers", component=SockHandlers, version=(1, 0, 0)),
            requirements.PluginRequirement(name="lsof", plugin=lsof.Lsof, version=(1, 1, 0)),
            requirements.VersionRequirement(name="linuxutils", component=linux.LinuxUtilities, version=(2, 0, 0)),
            requirements.BooleanRequirement(name="unix",
                                            description=("Show UNIX domain Sockets only"),
                                            default=False,
                                            optional=True),
            requirements.ListRequirement(name="pids",
                                         description="Filter results by process IDs. "
                                                     "It takes the root PID namespace identifiers.",
                                         element_type=int,
                                         optional=True),
            requirements.IntRequirement(name="netns",
                                        description="Filter results by network namespace. "
                                                    "Otherwise, all of them are shown.",
                                        optional=True),
        ]

    @classmethod
    def list_sockets(cls,
                     context: interfaces.context.ContextInterface,
                     vmlinux_module_name: str,
                     filter_func: Callable[[int], bool] = lambda _: False):
        """
        Returns every single socket descriptors
        """
        vmlinux = context.modules[vmlinux_module_name]

        sfop_addr = vmlinux.object_from_symbol("socket_file_ops").vol.offset
        dfop_addr = vmlinux.object_from_symbol("sockfs_dentry_operations").vol.offset

        fd_generator = lsof.Lsof.list_fds(context, vmlinux.name, filter_func)
        for _pid, _task_comm, task, fd_fields in fd_generator:
            fd_num, filp, _full_path = fd_fields

            if filp.f_op not in (sfop_addr, dfop_addr):
                continue

            dentry = filp.get_dentry()
            if not dentry:
                continue

            d_inode = dentry.d_inode
            if not d_inode:
                continue

            socket_alloc = linux.LinuxUtilities.container_of(d_inode, "socket_alloc", "vfs_inode", vmlinux)
            _socket = socket_alloc.socket

            vfs_inode = socket_alloc.vfs_inode
            if not (_socket and vfs_inode):
                continue

            sock = _socket.sk.dereference()

            sock_type = sock.type
            family = sock.family

            sock_handler = SockHandlers(vmlinux, task)
            sock_fields = sock_handler.process_sock(sock)
            if not sock_fields:
                continue

            child_sock = sock_fields[0]
            protocol = child_sock.protocol if hasattr(child_sock, "protocol") else ""

            net = task.nsproxy.net_ns
            netns_id = net.proc_inum if net.has_member("proc_inum") else net.ns.inum
            yield task, netns_id, fd_num, family, sock_type, protocol, sock_fields

    def _generator(self):
        pids = self.config.get('pids')
        filter_func = lsof.pslist.PsList.create_pid_filter(pids)

        tasks_per_sock = {}
        socket_generator = self.list_sockets(self.context, self.config['kernel'], filter_func=filter_func)
        for task, netns, fd_num, family, sock_type, protocol, sock_fields in socket_generator:
            if self.config['netns'] and self.config['netns'] != netns:
                continue

            sock, sock_stat, extended = sock_fields

            task_comm = utility.array_to_string(task.comm)
            task_info = f"{task_comm},pid={task.pid},fd={fd_num}"
            if extended:
                extended_str = ",".join(f"{k}={v}" for k, v in extended.items())
                task_info = f"{task_info},{extended_str}"

            fields = netns, family, sock_type, protocol, *sock_stat

            sock_addr = sock.vol.offset
            tasks_per_sock.setdefault(sock_addr, {})
            tasks_per_sock[sock_addr].setdefault('tasks', [])
            tasks_per_sock[sock_addr]['tasks'].append(task_info)
            tasks_per_sock[sock_addr]['fields'] = fields

        for data in tasks_per_sock.values():
            task_list = [f"({task})" for task in data['tasks']]
            tasks = ",".join(task_list)

            fields = data['fields'] + (tasks,)
            yield (0, fields)

    def run(self):
        tree_grid_args = [("NetNS", int),
                          ("Family", str),
                          ("Type", str),
                          ("Proto", str),
                          ("Source Addr:Port", str),
                          ("Destination Addr:Port", str),
                          ("State", str),
                          ("Tasks", str)]

        return renderers.TreeGrid(tree_grid_args, self._generator())
