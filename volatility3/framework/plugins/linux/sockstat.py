# This file is Copyright 2021 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

import logging
from collections import defaultdict
from typing import Callable, Tuple, List, Dict

from volatility3.framework.renderers import format_hints
from volatility3.framework import renderers, interfaces, exceptions, constants, objects
from volatility3.framework.configuration import requirements
from volatility3.framework.interfaces import plugins
from volatility3.framework.objects import utility
from volatility3.framework.symbols import linux
from volatility3.plugins.linux import lsof


vollog = logging.getLogger(__name__)

class SockHandlers(interfaces.configuration.VersionableInterface):
    """Handles several socket families extracting the sockets information."""

    _required_framework_version = (2, 0, 0)

    _version = (1, 0, 0)

    def __init__(self, vmlinux):
        self._vmlinux = vmlinux
        self.net_devices = self.get_net_devices()

        self.sock_family_handlers = {
            'AF_XDP': self._xdp_sock_processor,
            'AF_UNIX': self._unix_sock_processor,
            'AF_INET': self._inet_sock_processor,
            'AF_INET6': self._inet_sock_processor,
            'AF_VSOCK': self._vsock_sock_processor,
            'AF_PACKET': self._packet_sock_processor,
            'AF_NETLINK': self._netlink_sock_processor,
            'AF_BLUETOOTH': self._bluetooth_sock_processor,
        }

    def get_net_devices(self) -> Dict:
        """Given a namespace ID it returns a dictionary mapping each network
        interface index (ifindex) to its network interface name:

        Args:
            netns_id: The network namespace ID

        Returns:
            netdevices_map: Mapping network interface index (ifindex) to network
                            interface name
        """
        net_devices = defaultdict(dict)

        net_symname = self._vmlinux.symbol_table_name + constants.BANG + 'net'
        net_device_symname = self._vmlinux.symbol_table_name + constants.BANG + 'net_device'

        nethead = self._vmlinux.object_from_symbol(symbol_name='net_namespace_list')
        for net in nethead.to_list(net_symname, 'list'):
            for net_dev in net.dev_base_head.to_list(net_device_symname, 'dev_list'):
                netns_id = net.get_inode()
                dev_name = utility.array_to_string(net_dev.name)
                net_devices[netns_id][net_dev.ifindex] = dev_name

        return net_devices

    def process_sock(self, sock: objects.StructType) -> Tuple[objects.StructType, Tuple[str, str, str], Dict]:
        """
        Takes a kernel generic `sock` object, and extracts the generic parameters - using the respective socket family.

        Returns a tuple containing:
            sock:           volatility object of the proper socket type (per socker family).
            saddr, sport:   source address and port.
            daddr, dport:   destination address and port.
            state:          socket state.
            extended:       dict with additional information for specific sockets.
        """

        # Even if the sock family is not supported, or the required types
        # are not present in the symbols, we can still show some general
        # information about the socket that may be helpful.
        sock_family = sock.get_family()
        saddr = daddr = sport = dport = None
        state = sock.get_state()
        extended = dict()

        sock_family_handler = self.sock_family_handlers.get(sock_family)
        if not sock_family_handler:
            vollog.log(constants.LOGLEVEL_V, "Unsupported socket family '%s'", sock_family)
        else:
            try:
                sock, (saddr, sport, daddr, dport, state) = sock_family_handler(sock)
                extended = self.get_extended_socket_information(sock)
            except exceptions.SymbolError as e:
                vollog.log(constants.LOGLEVEL_V, "Error processing socket socket family '%s': %s", sock_family, e)


        return sock, \
            saddr or renderers.NotApplicableValue(), \
            sport or renderers.NotApplicableValue(), \
            daddr or renderers.NotApplicableValue(), \
            dport or renderers.NotApplicableValue(), \
            state or renderers.NotApplicableValue(), \
            extended

    def _extract_socket_filter_info(self, sock_filter: objects.Pointer, extended: dict) -> None:
        extended['bpf_filter_type'] = 'cBPF'

        if not sock_filter.has_member('prog') or not sock_filter.prog:
            return

        # BPF_PROG_TYPE_UNSPEC = 0
        bpfprog = sock_filter.prog
        if bpfprog.type > 0:
            extended['bpf_filter_type'] = 'eBPF'
            bpfprog_aux = bpfprog.aux
            if bpfprog_aux:
                extended['bpf_filter_id'] = str(bpfprog_aux.id)
                bpfprog_name = utility.array_to_string(bpfprog_aux.name)
                if bpfprog_name:
                    extended['bpf_filter_name'] = bpfprog_name

    def get_extended_socket_information(self, sock: objects.Pointer) -> dict:
        """
        Get infomation from the socket and reuseport filters
        """
        extended = dict()

        if sock.has_member('sk_filter') and sock.sk_filter:
            sock_filter = sock.sk_filter
            extended['filter_type'] = 'socket_filter'
            self._extract_socket_filter_info(sock_filter, extended)

        if sock.has_member('sk_reuseport_cb') and sock.sk_reuseport_cb:
            sock_reuseport_cb = sock.sk_reuseport_cb
            extended['filter_type'] = 'reuseport_filter'
            self._extract_socket_filter_info(sock_reuseport_cb, extended)
        
        return extended

    def _unix_sock_processor(self, sock: objects.StructType) -> Tuple[objects.StructType, Tuple[str, str, str]]:
        unix_sock = sock.cast('unix_sock')
        state = unix_sock.get_state()
        saddr = unix_sock.get_name()
        sinode = unix_sock.get_inode()
        
        daddr = dinode = None
        if unix_sock.peer != 0:
            peer = unix_sock.peer.dereference().cast('unix_sock')
            daddr = peer.get_name()
            dinode = peer.get_inode()

        return unix_sock, (saddr, sinode, daddr, dinode, state)

    def _inet_sock_processor(self, sock: objects.StructType) -> Tuple[objects.StructType, Tuple[str, str, str]]:
        inet_sock = sock.cast('inet_sock')
        saddr = inet_sock.get_src_addr()
        sport = inet_sock.get_src_port()
        daddr = inet_sock.get_dst_addr()
        dport = inet_sock.get_dst_port()
        state = inet_sock.get_state()

        if inet_sock.get_family() == 'AF_INET6':
            saddr = f'[{saddr}]'

        return inet_sock, (saddr, sport, daddr, dport, state)

    def _netlink_sock_processor(self, sock: objects.StructType) -> Tuple[objects.StructType, Tuple[str, str, str]]:
        netlink_sock = sock.cast('netlink_sock')
        saddr = sport = daddr = dport = None

        if netlink_sock.groups != 0:
            groups_bitmap = netlink_sock.groups.dereference()
            saddr = f'group:0x{groups_bitmap:08x}'
        sport = netlink_sock.portid

        daddr = f'group:0x{netlink_sock.dst_group:08x}'
        dport = netlink_sock.dst_portid

        module = netlink_sock.module
        if module and netlink_sock.module.name:
            module_name_str = utility.array_to_string(netlink_sock.module.name)
            daddr = f'{daddr},lkm:{module_name_str}'

        state = netlink_sock.get_state()
        return netlink_sock, (saddr, sport, daddr, dport, state)

    def _vsock_sock_processor(self, sock: objects.StructType) -> Tuple[objects.StructType, Tuple[str, str, str]]:
        vsock_sock = sock.cast('vsock_sock')
        saddr = vsock_sock.local_addr.svm_cid
        sport = vsock_sock.local_addr.svm_port
        daddr = vsock_sock.remote_addr.svm_cid
        dport = vsock_sock.remote_addr.svm_port

        state = vsock_sock.get_state()
        return vsock_sock, (saddr, sport, daddr, dport, state)

    def _packet_sock_processor(self, sock: objects.StructType) -> Tuple[objects.StructType, Tuple[str, str, str]]:
        packet_sock = sock.cast('packet_sock')
        ifindex = packet_sock.ifindex
        dev_name = self.net_devices.get(ifindex, None) if ifindex else 'ANY'

        state = packet_sock.get_state()
        return packet_sock, (dev_name, None, None, None, state)

    def _xdp_sock_processor(self, sock: objects.StructType) -> Tuple[objects.StructType, Tuple[str, str, str]]:
        xdp_sock = sock.cast('xdp_sock')
        device = xdp_sock.dev
        if not device:
            return

        saddr = utility.array_to_string(device.name)

        bpfprog = device.xdp_prog
        if not bpfprog:
            return

        bpfprog_aux = bpfprog.aux
        if bpfprog_aux:
            bpfprog_id = bpfprog_aux.id
            daddr = f'ebpf_prog_id:{bpfprog_id}'
            bpf_name = utility.array_to_string(bpfprog_aux.name)
            if bpf_name:
                daddr += f',ebpf_prog_name:{bpf_name}'
        else:
            daddr = None

        # Hallelujah, xdp_sock.state is an enum
        xsk_state = xdp_sock.state.lookup()
        state = xsk_state.replace('XSK_', '')

        return xdp_sock, (saddr, None, daddr, None, state)

    def _bluetooth_sock_processor(self, sock: objects.StructType) -> Tuple[objects.StructType, Tuple[str, str, str]]:
        bt_sock = sock.cast('bt_sock')

        def bt_addr(addr):
            return ':'.join(reversed(['%02x' % x for x in addr.b]))

        saddr = daddr = channel = None

        bt_protocol = bt_sock.get_protocol()
        if bt_protocol == 'HCI':
            pinfo = bt_sock.cast('hci_pinfo')
        elif bt_protocol == 'L2CAP':
            pinfo = bt_sock.cast('l2cap_pinfo')
            saddr = bt_addr(pinfo.chan.src)
            daddr = bt_addr(pinfo.chan.dst)
        elif bt_protocol == 'RFCOMM':
            pinfo = bt_sock.cast('rfcomm_pinfo')
            saddr = bt_addr(pinfo.src)
            daddr = bt_addr(pinfo.dst)
            channel = pinfo.channel
        else:
            vollog.log(constants.LOGLEVEL_V, 'Unsupported bluetooth protocol %s', bt_protocol)

        state = bt_sock.get_state()
        return bt_sock, (saddr, channel, daddr, None, state)

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
                     symbol_table: str,
                     filter_func: Callable[[int], bool] = lambda _: False):
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
            sock_fields: A tuple with the *_sock object, the sock stats and the
                         extended info dictionary
        """
        vmlinux = context.modules[symbol_table]
        sock_handlers = SockHandlers(vmlinux)

        sfop_addr = vmlinux.object_from_symbol("socket_file_ops").vol.offset
        dfop_addr = vmlinux.object_from_symbol("sockfs_dentry_operations").vol.offset

        for pid, comm, task, fd_fields in lsof.Lsof.list_fds(context, vmlinux.name, filter_func):
            fd_num, filp, full_path = fd_fields

            if filp.f_op not in (sfop_addr, dfop_addr):
                continue

            dentry = filp.get_dentry()
            if not dentry:
                continue

            d_inode = dentry.d_inode
            if not d_inode:
                continue

            socket_alloc = linux.LinuxUtilities.container_of(d_inode, "socket_alloc", "vfs_inode", vmlinux)
            socket = socket_alloc.socket

            if not (socket and socket.sk):
                continue

            net = task.nsproxy.net_ns
            netns_id = net.get_inode()

            sock = socket.sk.dereference()
            sock_type = sock.get_type()
            family = sock.get_family()

            sock, saddr, sport, daddr, dport, state, extended = sock_handlers.process_sock(sock)
            protocol = sock.get_protocol() or renderers.NotApplicableValue()

            yield task, netns_id, fd_num, sock, family, sock_type, protocol, saddr, sport, daddr, dport, state, extended

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
            source: Source address string
            destination: Destination address string
            state: State strings (LISTEN, CONNECTED, etc)
            tasks: String with a list of tasks and FDs using a socket. It can also have
                   exteded information such as socket filters, bpf info, etc.
        """
        filter_func = lsof.pslist.PsList.create_pid_filter(pids)
        sockets = dict()

        for task, netns_id, fd_num, sock, family, sock_type, protocol, saddr, sport, daddr, dport, state, extended \
            in self.list_sockets(self.context, symbol_table, filter_func=filter_func):

            # filter by network ns if active - TODO: move outside
            if netns_id_arg and netns_id_arg != netns_id:
                continue
            
            ext_info_encoded = ','.join(f'{k}={v}' for k, v in extended.items())
            yield (0, (format_hints.Hex(sock.vol.offset), netns_id, task.pid,
                       family, sock_type, protocol,
                       saddr, sport, daddr, dport,
                       state, ext_info_encoded))

    def run(self):
        pids = self.config.get('pids')
        netns_id = self.config['netns']
        symbol_table = self.config['kernel']

        tree_grid_args = [("Offset", format_hints.Hex),
                          ("NetNS", int),
                          ("Pid", int),
                          ("Family", str),
                          ("Type", str),
                          ("Proto", str),
                          ("Src Addr", str),
                          ("Src Port", int),
                          ("Dst Addr", str),
                          ("Dst Port", int),
                          ("State", str),
                          ("Extended", str)]

        return renderers.TreeGrid(tree_grid_args, self._generator(pids, netns_id, symbol_table))
