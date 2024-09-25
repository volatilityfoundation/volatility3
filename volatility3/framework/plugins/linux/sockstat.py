# This file is Copyright 2021 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

import logging
from typing import Callable, Tuple, List, Dict

from volatility3.framework import interfaces, exceptions, constants, objects
from volatility3.framework.renderers import TreeGrid, NotAvailableValue, format_hints
from volatility3.framework.configuration import requirements
from volatility3.framework.interfaces import plugins
from volatility3.framework.objects import utility
from volatility3.framework.symbols import linux
from volatility3.plugins.linux import lsof


vollog = logging.getLogger(__name__)


class SockHandlers(interfaces.configuration.VersionableInterface):
    """Handles several socket families extracting the sockets information."""

    _required_framework_version = (2, 0, 0)

    _version = (2, 0, 0)

    def __init__(self, vmlinux, task):
        self._vmlinux = vmlinux
        self._task = task

        try:
            netns_id = task.nsproxy.net_ns.get_inode()
        except AttributeError:
            netns_id = NotAvailableValue()

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

    def _build_network_devices_map(self, netns_id: int) -> Dict:
        """Given a namespace ID it returns a dictionary mapping each network
        interface index (ifindex) to its network interface name:

        Args:
            netns_id: The network namespace ID

        Returns:
            netdevices_map: Mapping network interface index (ifindex) to network
                            interface name
        """
        netdevices_map = {}
        nethead = self._vmlinux.object_from_symbol(symbol_name="net_namespace_list")
        net_symname = self._vmlinux.symbol_table_name + constants.BANG + "net"
        for net in nethead.to_list(net_symname, "list"):
            net_device_symname = (
                self._vmlinux.symbol_table_name + constants.BANG + "net_device"
            )
            for net_dev in net.dev_base_head.to_list(net_device_symname, "dev_list"):
                if (
                    isinstance(netns_id, NotAvailableValue)
                    or net.get_inode() != netns_id
                ):
                    continue
                dev_name = utility.array_to_string(net_dev.name)
                netdevices_map[net_dev.ifindex] = dev_name
        return netdevices_map

    def process_sock(
        self, sock: objects.StructType
    ) -> Tuple[objects.StructType, Tuple[str, str, str], Dict]:
        """Takes a kernel generic `sock` object and processes it with its respective socket family

        Args:
            sock: Kernel generic `sock` object

        Returns a tuple with:
            sock: The respective kernel's \\*_sock object for that socket family
            sock_stat: A tuple with the source and destination (address and port) along with its state string
            socket_filter: A dictionary with information about the socket filter
        """
        family = sock.get_family()
        socket_filter = {}
        sock_handler = self._sock_family_handlers.get(family)
        if sock_handler:
            try:
                unix_sock, sock_stat = sock_handler(sock)
                self._update_socket_filters_info(sock, socket_filter)

                return unix_sock, sock_stat, socket_filter
            except exceptions.SymbolError as e:
                # Cannot finds the *_sock type in the symbols
                vollog.log(
                    constants.LOGLEVEL_V,
                    "Error processing socket family '%s': %s",
                    family,
                    e,
                )
        else:
            vollog.log(constants.LOGLEVEL_V, "Unsupported family '%s'", family)

        # Even if the sock family is not supported, or the required types
        # are not present in the symbols, we can still show some general
        # information about the socket that may be helpful.
        src_addr = src_port = dst_addr = dst_port = None
        state = sock.get_state()

        sock_stat = src_addr, src_port, dst_addr, dst_port, state

        return sock, sock_stat, socket_filter

    def _update_socket_filters_info(
        self, sock: objects.Pointer, socket_filter: dict
    ) -> None:
        """Get information from the socket and reuseport filters

        Args:
            sock: The kernel sock (sk) struct
            socket_filter: A dictionary with information about the socket filter
        """
        if sock.has_member("sk_filter") and sock.sk_filter:
            sock_filter = sock.sk_filter
            socket_filter["filter_type"] = "socket_filter"
            self._extract_socket_filter_info(sock_filter, socket_filter)

        if sock.has_member("sk_reuseport_cb") and sock.sk_reuseport_cb:
            sock_reuseport_cb = sock.sk_reuseport_cb
            socket_filter["filter_type"] = "reuseport_filter"
            self._extract_socket_filter_info(sock_reuseport_cb, socket_filter)

    def _extract_socket_filter_info(
        self, sock_filter: objects.Pointer, socket_filter: dict
    ) -> None:
        """Get specific information for each type of filter

        Args:
            socket_filter: A dictionary with information about the socket filter
        """
        socket_filter["bpf_filter_type"] = "cBPF"

        if not sock_filter.has_member("prog") or not sock_filter.prog:
            return None

        bpfprog = sock_filter.prog

        bpfprog_type = bpfprog.get_type()
        if not bpfprog_type:
            # kernel < 3.18.140, it's a cBPF filter
            return None

        if bpfprog_type == "BPF_PROG_TYPE_UNSPEC":
            return None  # cBPF filter

        if bpfprog_type != "BPF_PROG_TYPE_SOCKET_FILTER":
            socket_filter["bpf_filter_type"] = f"UNK({bpfprog_type})"
            vollog.warning(f"Unexpected BPF type {bpfprog_type} for a socket")
            return None

        socket_filter["bpf_filter_type"] = "eBPF"
        if not bpfprog.has_member("aux") or not bpfprog.aux:
            return  # kernel < 3.18.140
        bpfprog_aux = bpfprog.aux

        if bpfprog_aux.has_member("id"):
            # `id` member was added to `bpf_prog_aux` in kernels 4.13.16
            socket_filter["bpf_filter_id"] = str(bpfprog_aux.id)
        if bpfprog_aux.has_member("name"):
            # `name` was added to `bpf_prog_aux` in kernels 4.15.18
            bpfprog_name = utility.array_to_string(bpfprog_aux.name)
            if bpfprog_name:
                socket_filter["bpf_filter_name"] = bpfprog_name

    def _unix_sock(
        self, sock: objects.StructType
    ) -> Tuple[objects.StructType, Tuple[str, str, str]]:
        """Handles the AF_UNIX socket family

        Args:
            sock: Kernel generic `sock` object

        Returns:
            unix_sock: The kernel's `unix_sock` object
            sock_stat: A tuple with the source and destination (address and port) along with its state string
        """
        unix_sock = sock.cast("unix_sock")
        state = unix_sock.get_state()
        src_addr = unix_sock.get_name()
        src_port = unix_sock.get_inode()

        if unix_sock.peer:
            peer = unix_sock.peer.dereference().cast("unix_sock")
            dst_addr = peer.get_name()
            dst_port = peer.get_inode()
        else:
            dst_addr = dst_port = None

        sock_stat = src_addr, src_port, dst_addr, dst_port, state
        return unix_sock, sock_stat

    def _inet_sock(
        self, sock: objects.StructType
    ) -> Tuple[objects.StructType, Tuple[str, str, str]]:
        """Handles the AF_INET/6 socket families

        Args:
            sock: Kernel generic `sock` object

        Returns:
            inet_sock: The kernel's `inet_sock` object
            sock_stat: A tuple with the source and destination (address and port) along with its state string
        """
        inet_sock = sock.cast("inet_sock")
        src_addr = inet_sock.get_src_addr()
        src_port = inet_sock.get_src_port()
        dst_addr = inet_sock.get_dst_addr()
        dst_port = inet_sock.get_dst_port()
        state = inet_sock.get_state()

        sock_stat = src_addr, src_port, dst_addr, dst_port, state
        return inet_sock, sock_stat

    def _netlink_sock(
        self, sock: objects.StructType
    ) -> Tuple[objects.StructType, Tuple[str, str, str]]:
        """Handles the AF_NETLINK socket family

        Args:
            sock: Kernel generic `sock` object

        Returns:
            netlink_sock: The kernel's `netlink_sock` object
            sock_stat: A tuple with the source and destination (address and port) along with its state string
        """
        netlink_sock = sock.cast("netlink_sock")

        src_addr = None
        if netlink_sock.groups:
            groups_bitmap = netlink_sock.groups.dereference()
            src_addr = f"groups:0x{groups_bitmap:08x}"

        try:
            # Kernel >= 3.7.10
            src_port = netlink_sock.get_portid()
        except AttributeError:
            src_port = NotAvailableValue()

        dst_addr = f"group:0x{netlink_sock.dst_group:08x}"
        module = netlink_sock.module
        if module and module.name:
            module_name_str = utility.array_to_string(module.name)
            dst_addr = f"{dst_addr},lkm:{module_name_str}"
        try:
            dst_port = netlink_sock.get_dst_portid()
        except AttributeError:
            dst_port = NotAvailableValue()

        state = netlink_sock.get_state()

        sock_stat = src_addr, src_port, dst_addr, dst_port, state
        return netlink_sock, sock_stat

    def _vsock_sock(
        self, sock: objects.StructType
    ) -> Tuple[objects.StructType, Tuple[str, str, str]]:
        """Handles the AF_VSOCK socket family

        Args:
            sock: Kernel generic `sock` object

        Returns:
            vsock_sock: The kernel `vsock_sock` object
            sock_stat: A tuple with the source and destination (address and port) along with its state string
        """
        vsock_sock = sock.cast("vsock_sock")
        src_addr = vsock_sock.local_addr.svm_cid
        src_port = vsock_sock.local_addr.svm_port
        dst_addr = vsock_sock.remote_addr.svm_cid
        dst_port = vsock_sock.remote_addr.svm_port
        state = vsock_sock.get_state()

        sock_stat = src_addr, src_port, dst_addr, dst_port, state
        return vsock_sock, sock_stat

    def _packet_sock(
        self, sock: objects.StructType
    ) -> Tuple[objects.StructType, Tuple[str, str, str]]:
        """Handles the AF_PACKET socket family

        Args:
            sock: Kernel generic `sock` object

        Returns:
            packet_sock: The kernel's `packet_sock` object
            sock_stat: A tuple with the source and destination (address and port) along with its state string
        """
        packet_sock = sock.cast("packet_sock")
        ifindex = packet_sock.ifindex
        dev_name = self._netdevices.get(ifindex) if ifindex > 0 else "ANY"

        src_addr = dev_name
        src_port = dst_addr = dst_port = None
        state = packet_sock.get_state()

        sock_stat = src_addr, src_port, dst_addr, dst_port, state
        return packet_sock, sock_stat

    def _xdp_sock(
        self, sock: objects.StructType
    ) -> Tuple[objects.StructType, Tuple[str, str, str]]:
        """Handles the AF_XDP socket family

        Args:
            sock: Kernel generic `sock` object

        Returns:
            xdp_sock: The kernel's `xdp_sock` object
            sock_stat: A tuple with the source and destination (address and port) along with its state string
        """
        xdp_sock = sock.cast("xdp_sock")
        device = xdp_sock.dev
        if not device:
            return None

        src_addr = utility.array_to_string(device.name)
        src_port = dst_addr = dst_port = None

        bpfprog = device.xdp_prog
        if not bpfprog:
            return None

        if not bpfprog.has_member("aux") or not bpfprog.aux:
            return None

        bpfprog_aux = bpfprog.aux
        if bpfprog_aux.has_member("id"):
            # `id` member was added to `bpf_prog_aux` in kernels 4.13
            bpfprog_id = bpfprog_aux.id
            dst_port = f"ebpf_prog_id:{bpfprog_id}"
        if bpfprog_aux.has_member("name"):
            # `name` was added to `bpf_prog_aux` in kernels 4.15
            bpf_name = utility.array_to_string(bpfprog_aux.name)
            if bpf_name:
                dst_addr = f"ebpf_prog_name:{bpf_name}"

        xsk_state = xdp_sock.get_state()
        state = xsk_state.replace("XSK_", "")

        sock_stat = src_addr, src_port, dst_addr, dst_port, state
        return xdp_sock, sock_stat

    def _bluetooth_sock(
        self, sock: objects.StructType
    ) -> Tuple[objects.StructType, Tuple[str, str, str]]:
        """Handles the AF_BLUETOOTH socket family

        Args:
            sock: Kernel generic `sock` object

        Returns:
            bt_sock: The kernel's `bt_sock` object
            sock_stat: A tuple with the source and destination (address and port) along with its state string
        """
        bt_sock = sock.cast("bt_sock")

        def bt_addr(addr):
            return ":".join(reversed(["%02x" % x for x in addr.b]))

        src_addr = src_port = dst_addr = dst_port = None
        bt_protocol = bt_sock.get_protocol()
        if bt_protocol == "HCI":
            if self._vmlinux.has_type("hci_pinfo"):
                pinfo = bt_sock.cast("hci_pinfo")
                if (
                    pinfo.has_member("hdev")
                    and self._vmlinux.has_type("hci_dev")
                    and pinfo.hdev.has_member("dev_name")
                ):
                    src_addr = utility.array_to_string(pinfo.hdev.dev_name)
            else:
                vollog.log(
                    constants.LOGLEVEL_V,
                    "Type definition for 'hci_pinfo' is not available in the symbols",
                )
        elif bt_protocol == "L2CAP":
            if self._vmlinux.has_type("l2cap_pinfo"):
                pinfo = bt_sock.cast("l2cap_pinfo")
                src_addr = bt_addr(pinfo.chan.src)
                dst_addr = bt_addr(pinfo.chan.dst)
                src_port = pinfo.chan.sport
                dst_port = pinfo.chan.psm
            else:
                vollog.log(
                    constants.LOGLEVEL_V,
                    "Type definition for 'l2cap_pinfo' is not available in the symbols",
                )
        elif bt_protocol == "RFCOMM":
            if self._vmlinux.has_type("rfcomm_pinfo"):
                pinfo = bt_sock.cast("rfcomm_pinfo")
                src_addr = bt_addr(pinfo.src)
                dst_addr = bt_addr(pinfo.dst)
                src_port = pinfo.channel
            else:
                vollog.log(
                    constants.LOGLEVEL_V,
                    "Type definition for 'rfcomm_pinfo' is not available in the symbols",
                )
        elif bt_protocol == "SCO":
            if self._vmlinux.has_type("sco_pinfo"):
                pinfo = bt_sock.cast("sco_pinfo")
                src_addr = bt_addr(pinfo.src)
                dst_addr = bt_addr(pinfo.dst)
            else:
                vollog.log(
                    constants.LOGLEVEL_V,
                    "Type definition for 'sco_pinfo' is not available in the symbols",
                )
        else:
            vollog.log(
                constants.LOGLEVEL_V, "Unsupported bluetooth protocol '%s'", bt_protocol
            )

        state = bt_sock.get_state()

        sock_stat = src_addr, src_port, dst_addr, dst_port, state
        return bt_sock, sock_stat


class Sockstat(plugins.PluginInterface):
    """Lists all network connections for all processes."""

    _required_framework_version = (2, 0, 0)

    _version = (1, 0, 0)

    @classmethod
    def get_requirements(cls):
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Linux kernel",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.VersionRequirement(
                name="SockHandlers", component=SockHandlers, version=(1, 0, 0)
            ),
            requirements.PluginRequirement(
                name="lsof", plugin=lsof.Lsof, version=(1, 1, 0)
            ),
            requirements.VersionRequirement(
                name="linuxutils", component=linux.LinuxUtilities, version=(2, 0, 0)
            ),
            requirements.BooleanRequirement(
                name="unix",
                description=("Show UNIX domain Sockets only"),
                default=False,
                optional=True,
            ),
            requirements.ListRequirement(
                name="pids",
                description="Filter results by process IDs. "
                "It takes the root PID namespace identifiers.",
                element_type=int,
                optional=True,
            ),
            requirements.IntRequirement(
                name="netns",
                description="Filter results by network namespace. "
                "Otherwise, all of them are shown.",
                optional=True,
            ),
        ]

    @classmethod
    def list_sockets(
        cls,
        context: interfaces.context.ContextInterface,
        symbol_table: str,
        filter_func: Callable[[int], bool] = lambda _: False,
    ):
        """Returns every single socket descriptor

        Args:
            context: The context to retrieve required elements (layers, symbol tables) from
            symbol_table: The name of the kernel module on which to operate
            filter_func: A function which takes a task object and returns True if the task should be ignored/filtered

        Yields:
            task: Kernel's task object
            netns_id: Network namespace ID
            fd_num: File descriptor number
            family: Socket family string (AF_UNIX, AF_INET, etc)
            sock_type: Socket type string (STREAM, DGRAM, etc)
            protocol: Protocol string (UDP, TCP, etc)
            sock_fields: A tuple with the \\*_sock object, the sock stats and the extended info dictionary
        """
        vmlinux = context.modules[symbol_table]

        sfop_addr = vmlinux.object_from_symbol("socket_file_ops").vol.offset
        dfop_addr = vmlinux.object_from_symbol("sockfs_dentry_operations").vol.offset

        fd_generator = lsof.Lsof.list_fds(context, vmlinux.name, filter_func)
        for _pid, task_comm, task, fd_fields in fd_generator:
            fd_num, filp, _full_path = fd_fields

            if filp.f_op not in (sfop_addr, dfop_addr):
                continue

            dentry = filp.get_dentry()
            if not dentry:
                continue

            d_inode = dentry.d_inode
            if not d_inode:
                continue

            socket_alloc = linux.LinuxUtilities.container_of(
                d_inode, "socket_alloc", "vfs_inode", vmlinux
            )
            socket = socket_alloc.socket

            if not (socket and socket.sk):
                continue

            sock = socket.sk.dereference()

            sock_type = sock.get_type()
            family = sock.get_family()

            sock_handler = SockHandlers(vmlinux, task)
            sock_fields = sock_handler.process_sock(sock)
            if not sock_fields:
                continue

            child_sock = sock_fields[0]
            protocol = child_sock.get_protocol()

            net = task.nsproxy.net_ns
            try:
                netns_id = net.get_inode()
            except AttributeError:
                netns_id = NotAvailableValue()

            yield task_comm, task, netns_id, fd_num, family, sock_type, protocol, sock_fields

    def _format_fields(self, sock_stat, protocol):
        """Prepare the socket fields to be rendered

        Args:
            sock_stat: A tuple with the source and destination (address and port) along with its state string
            protocol: Protocol string (UDP, TCP, etc)

        Returns:
            `sock_stat` and `protocol` formatted.
        """
        sock_stat = [
            NotAvailableValue() if field is None else str(field) for field in sock_stat
        ]
        if protocol is None:
            protocol = NotAvailableValue()

        return tuple(sock_stat), protocol

    def _generator(self, pids: List[int], netns_id_arg: int, symbol_table: str):
        """Enumerate tasks sockets. Each row represents a kernel socket.

        Args:
            pids: List of PIDs to filter. If a empty list or
            netns_id_arg: If a network namespace ID is set, it will only show this namespace.
            symbol_table: The name of the kernel module on which to operate

        Yields:
            netns_id: Network namespace ID
            family: Socket family string (AF_UNIX, AF_INET, etc)
            sock_type: Socket type string (STREAM, DGRAM, etc)
            protocol: Protocol string (UDP, TCP, etc)
            source addr: Source address string
            source port: Source port string (not all of them are int)
            destination addr: Destination address string
            destination port: Destination port (not all of them are int)
            state: State strings (LISTEN, CONNECTED, etc)
            tasks: String with a list of tasks and FDs using a socket. It can also have
                   extended information such as socket filters, bpf info, etc.
        """
        filter_func = lsof.pslist.PsList.create_pid_filter(pids)
        socket_generator = self.list_sockets(
            self.context, symbol_table, filter_func=filter_func
        )

        for (
            task_comm,
            task,
            netns_id,
            fd_num,
            family,
            sock_type,
            protocol,
            sock_fields,
        ) in socket_generator:
            if netns_id_arg and netns_id_arg != netns_id:
                continue

            sock, sock_stat, extended = sock_fields
            sock_stat, protocol = self._format_fields(sock_stat, protocol)

            socket_filter_str = (
                ",".join(f"{k}={v}" for k, v in extended.items())
                if extended
                else NotAvailableValue()
            )

            fields = (
                netns_id,
                task_comm,
                task.pid,
                fd_num,
                format_hints.Hex(sock.vol.offset),
                family,
                sock_type,
                protocol,
                *sock_stat,
                socket_filter_str,
            )

            yield (0, fields)

    def run(self):
        pids = self.config.get("pids")
        netns_id = self.config["netns"]
        symbol_table = self.config["kernel"]

        tree_grid_args = [
            ("NetNS", int),
            ("Process Name", str),
            ("Pid", int),
            ("FD", int),
            ("Sock Offset", format_hints.Hex),
            ("Family", str),
            ("Type", str),
            ("Proto", str),
            ("Source Addr", str),
            ("Source Port", str),
            ("Destination Addr", str),
            ("Destination Port", str),
            ("State", str),
            ("Filter", str),
        ]

        return TreeGrid(tree_grid_args, self._generator(pids, netns_id, symbol_table))
