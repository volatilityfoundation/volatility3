# This file is Copyright 2021 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

import logging
from collections import defaultdict
from typing import Callable, Tuple, List, Dict

from volatility3.framework.renderers import NotApplicableValue, format_hints
from volatility3.framework import renderers, interfaces, exceptions, constants, objects
from volatility3.framework.configuration import requirements
from volatility3.framework.interfaces import plugins
from volatility3.framework.objects import utility
from volatility3.framework.symbols import linux
from volatility3.plugins.linux import lsof


vollog = logging.getLogger(__name__)



UnifiedSocketHandlers = dict()

def unified_socket_handler(*sock_families):
    """
    Decorator for registering functions as unified socket handlers,
        to make them accessible through the `UnifiedSocketHandlers` dictionary,
        under the registered `sock_families` names.

    A unified socket handler receives a `sock` object as an argument,
        and returns a tuple of `sock, (saddr, sport, daddr, dport, state)`.
    """
    def wrapper(sock_handler):
        for family in sock_families:
            UnifiedSocketHandlers[family] = sock_handler
        return sock_handler
    return wrapper



class SocketHandlers(interfaces.configuration.VersionableInterface):
    """
    Handles several socket families extracting the sockets information.
    """

    _version = (1, 0, 0)
    _required_framework_version = (2, 0, 0)

    def __init__(self, vmlinux):
        self.net_devices = self.get_net_devices(vmlinux)

    @classmethod
    def get_net_devices(cls, vmlinux) -> Dict:
        """
        Returns a dictionary, mapping network namespaces to dictionaries of interface index and names, as pairs.
        
        scheme: `{net_namespace: {if_index: if_name}}`
        """
        net_devices = defaultdict(dict)

        net_symname = vmlinux.symbol_table_name + constants.BANG + 'net'
        net_device_symname = vmlinux.symbol_table_name + constants.BANG + 'net_device'

        nethead = vmlinux.object_from_symbol(symbol_name='net_namespace_list')
        for net in nethead.to_list(net_symname, 'list'):
            for net_dev in net.dev_base_head.to_list(net_device_symname, 'dev_list'):
                netns_no = net.get_inode()
                dev_name = utility.array_to_string(net_dev.name)
                net_devices[netns_no][net_dev.ifindex] = dev_name

        return net_devices

    def get_unified_socket(self, sock, netns_no):
        """
        Takes a kernel generic `sock` object, and extracts the generic parameters - using the respective socket family.

        Returns a tuple containing:
            sock:           volatility object of the proper socket type (per socker family).
            protocol:       socket protocol.
            saddr, sport:   source address and port.
            daddr, dport:   destination address and port.
            state:          socket state.
            extended:       dict with additional information for specific sockets.
        """
        family = sock.get_family()
        state = sock.get_state()
        saddr = daddr = sport = dport = None
        extended = None

        sock_family_handler = UnifiedSocketHandlers.get(family)
        if not sock_family_handler:
            vollog.log(constants.LOGLEVEL_V, f'Unsupported socket family {family}')
        else:
            try:
                sock, (saddr, sport, daddr, dport, state) = sock_family_handler(sock, net_devices=self.net_devices.get(netns_no))
                extended = self.get_socket_extended_information(sock)
            except exceptions.SymbolError as e:
                vollog.log(constants.LOGLEVEL_V, f'Error processing socket socket family {family}: {e}')

        protocol = sock.get_protocol()

        return sock, \
            protocol or NotApplicableValue(), \
            saddr or NotApplicableValue(), \
            sport or NotApplicableValue(), \
            daddr or NotApplicableValue(), \
            dport or NotApplicableValue(), \
            state or NotApplicableValue(), \
            extended

    def get_socket_filter_information(self, sock_filter):
        if not sock_filter.has_member('prog') or not sock_filter.prog:
            return

        # BPF_PROG_TYPE_UNSPEC = 0
        bpf_prog = sock_filter.prog
        if bpf_prog.type > 0:
            if bpf_prog.aux:
                bpf_prog_name = utility.array_to_string(bpf_prog.aux.name)
                return dict(bpf_filter_type='eBPF', bpf_filter_id=str(bpf_prog.aux.id), bpf_filter_name=bpf_prog_name)
            else:
                return dict(bpf_filter_type='eBPF')
        else:
            return dict(bpf_filter_type='cBPF')

    def get_socket_extended_information(self, sock):
        data = dict()

        if sock.has_member('sk_filter') and sock.sk_filter:
            data['socket_filter'] = self.get_socket_filter_information(sock.sk_filter)

        elif sock.has_member('sk_reuseport_cb') and sock.sk_reuseport_cb:
            data['reuseport_filter'] = self.get_socket_filter_information(sock.sk_reuseport_cb)

        return data

    @unified_socket_handler('AF_UNIX')
    def unix_sock_handler(sock, **kwargs):
        unix_sock = sock.cast('unix_sock')
        state = unix_sock.get_state()
        saddr = unix_sock.get_name()
        sinode = unix_sock.get_inode()
        
        daddr = dinode = None
        if unix_sock.peer:
            peer = unix_sock.peer.dereference().cast('unix_sock')
            daddr = peer.get_name()
            dinode = peer.get_inode()

        return unix_sock, (saddr, sinode, daddr, dinode, state)

    @unified_socket_handler('AF_INET', 'AF_INET6')
    def inet_sock_handler(sock, **kwargs):
        inet_sock = sock.cast('inet_sock')
        saddr = inet_sock.get_src_addr()
        sport = inet_sock.get_src_port()
        daddr = inet_sock.get_dst_addr()
        dport = inet_sock.get_dst_port()

        state = inet_sock.get_state()
        return inet_sock, (saddr, sport, daddr, dport, state)

    @unified_socket_handler('AF_VSOCK')
    def vsock_sock_handler(sock, **kwargs):
        vsock_sock = sock.cast('vsock_sock')
        saddr = vsock_sock.local_addr.svm_cid
        sport = vsock_sock.local_addr.svm_port
        daddr = vsock_sock.remote_addr.svm_cid
        dport = vsock_sock.remote_addr.svm_port

        state = vsock_sock.get_state()
        return vsock_sock, (saddr, sport, daddr, dport, state)

    @unified_socket_handler('AF_NETLINK')
    def netlink_sock_handler(sock, **kwargs):
        netlink_sock = sock.cast('netlink_sock')
        saddr = sport = daddr = dport = None

        sport = netlink_sock.portid
        dport = netlink_sock.dst_portid

        if netlink_sock.groups:
            saddr = f'group:0x{netlink_sock.groups.dereference():08x}'

        if netlink_sock.dst_group:
            daddr = f'group:0x{netlink_sock.dst_group:08x}'
        elif netlink_sock.module:
            mod_name = utility.array_to_string(netlink_sock.module.name)
            daddr = f'lkm:{mod_name}'

        state = netlink_sock.get_state()
        return netlink_sock, (saddr, sport, daddr, dport, state)

    @unified_socket_handler('AF_PACKET')
    def packet_sock_handler(sock, net_devices, **kwargs):
        packet_sock = sock.cast('packet_sock')
        ifindex = packet_sock.ifindex
        device = net_devices.get(ifindex, None) if ifindex else 'ANY'

        state = packet_sock.get_state()
        return packet_sock, (device, ifindex, None, None, state)

    @unified_socket_handler('AF_XDP')
    def xdp_sock_handler(sock, **kwargs):
        xdp_sock = sock.cast('xdp_sock')
        saddr = daddr = sport = dport = None

        device = xdp_sock.dev
        if device:
            saddr = utility.array_to_string(device.name)

            bpf_prog = device.xdp_prog
            if bpf_prog and bpf_prog.aux:
                bpf_name = utility.array_to_string(bpf_prog.aux.name)
                daddr = f'ebpf_prog_id:{bpf_prog.aux.id}'
                dport = f'ebpf_prog_name:{bpf_name}'

        state = xdp_sock.state.lookup()
        return xdp_sock, (saddr, sport, daddr, dport, state)

    @unified_socket_handler('AF_BLUETOOTH')
    def bluetooth_sock_handler(sock, **kwargs):
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

    _version = (1, 0, 0)
    _required_framework_version = (2, 0, 0)

    @classmethod
    def get_requirements(cls):
        return [
            requirements.ModuleRequirement(name="kernel", description="Linux kernel", architectures=["Intel32", "Intel64"]),
            requirements.PluginRequirement(name="lsof", plugin=lsof.Lsof, version=(1, 1, 0)),
            requirements.VersionRequirement(name="SocketHandlers", component=SocketHandlers, version=(1, 0, 0)),
            requirements.VersionRequirement(name="linuxutils", component=linux.LinuxUtilities, version=(2, 0, 0)),

            requirements.IntRequirement(name="netns",
                                        description="Filter results by network namespace. Otherwise, all of them are shown.",
                                        optional=True),
            requirements.ListRequirement(name="pids",
                                         description="Filter results by process IDs. It takes the root PID namespace identifiers.",
                                         element_type=int, optional=True),
            requirements.BooleanRequirement(name="unix",
                                            description=("Show UNIX domain Sockets only"),
                                            default=False, optional=True),
        ]

    @classmethod
    def list_sockets(cls,
                     context: interfaces.context.ContextInterface,
                     symbol_table: str,
                     filter_func: Callable[[int], bool] = lambda _: False):
        """
        Iterates the sockets for each task in the `context`'s kernel, and returns the data in a uniform format.
        * `filter_func` may contain a function which takes a `task` object and decides whether to output it's sockets.

        Yields a tuple containing:
            task:           volatility task object
            netns_no:       network namespace id
            fd_num:         socket's file descriptor
            sock:           volatility socket object
            family:         socket family string (e.g. AF_UNIX, AF_INET)
            sock_type:      socket type as string (e.g. DGRAM, STREAM)
            protocol:       socket protocol as string (e.g. TCP, ETH)
            saddr, sport:   source address and port
            daddr, dport:   destination address and port
            state:          socket state
            extended:       additional information as dict
        """
        vmlinux = context.modules[symbol_table]
        sock_handlers = SocketHandlers(vmlinux)

        sfop_addr = vmlinux.object_from_symbol("socket_file_ops").vol.offset
        dfop_addr = vmlinux.object_from_symbol("sockfs_dentry_operations").vol.offset

        for task, fd_num, filp, full_path in lsof.Lsof.list_fds(context, vmlinux.name, filter_func):
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

            netns_no = task.nsproxy.net_ns.get_inode()

            sock = socket.sk.dereference()
            family = sock.get_family()
            sock_type = sock.get_type()

            sock, protocol, saddr, sport, daddr, dport, state, extended = sock_handlers.get_unified_socket(sock, netns_no)

            yield task, netns_no, fd_num, sock, family, sock_type, protocol, saddr, sport, daddr, dport, state, extended

    def _generator(self,
                   symbol_table: str,
                   pids_filter: List[int] = None,
                   netns_filter: int = None):
        """
        Prepare sockets enumerated by `list_sockets` for volatility output.

        Arguments:
            symbol_table:   the name of the kernel module layer.
            pids_filter:    show only results from this processes (if set).
            netns_filter:   show only results from this net namespace (if set).
        """
        filter_func = lsof.pslist.PsList.create_pid_filter(pids_filter)

        for task, netns_no, fd_num, sock, family, sock_type, protocol, saddr, sport, daddr, dport, state, extended \
            in self.list_sockets(self.context, symbol_table, filter_func=filter_func):

            # filter by network ns if active
            if netns_filter and netns_filter != netns_no:
                continue
            
            ext_info_encoded = ','.join(f'{k}={v}' for k, v in extended.items()) if extended else NotApplicableValue()
            yield (0, (
                format_hints.Hex(sock.vol.offset), netns_no, task.pid,
                family, sock_type, protocol,
                saddr, sport, daddr, dport,
                state, ext_info_encoded
            ))

    def run(self):
        pids_filter = self.config.get('pids')
        netns_filter = self.config['netns']
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

        return renderers.TreeGrid(
            tree_grid_args,
            self._generator(symbol_table, pids_filter, netns_filter))
