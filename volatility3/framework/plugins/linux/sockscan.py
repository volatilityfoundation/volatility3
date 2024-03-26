# This file is Copyright 2024 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

import logging
import struct
from typing import Callable, Tuple, List, Dict

from volatility3.framework import interfaces, exceptions, constants, objects
from volatility3.framework.renderers import TreeGrid, NotAvailableValue, format_hints
from volatility3.framework.configuration import requirements
from volatility3.framework.interfaces import plugins
from volatility3.framework.objects import utility
from volatility3.framework.symbols import linux
from volatility3.plugins.linux import sockstat
from volatility3.framework import symbols
from volatility3.framework import symbols, constants
from volatility3.framework.layers import scanners

vollog = logging.getLogger(__name__)


class Sockscan(plugins.PluginInterface):
    """Scans for network connections found in memory layer."""

    _required_framework_version = (2, 6, 0)

    @classmethod
    def get_requirements(cls):
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Linux kernel",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.VersionRequirement(
                name="SockHandlers", component=sockstat.SockHandlers, version=(1, 0, 0)
            ),
            requirements.VersionRequirement(
                name="linuxutils", component=linux.LinuxUtilities, version=(2, 0, 0)
            ),
        ]

    def _generator(self, symbol_table_name: str):
        """Scans for sockets. Each row represents a kernel socket.

        Args:
            symbol_table_name: The name of the kernel module on which to operate

        Yields:
            family: Socket family string (AF_UNIX, AF_INET, etc)
            sock_type: Socket type string (STREAM, DGRAM, etc)
            protocol: Protocol string (UDP, TCP, etc)
            source addr: Source address string
            source port: Source port string (not all of them are int)
            destination addr: Destination address string
            destination port: Destination port (not all of them are int)
            state: State strings (LISTEN, CONNECTED, etc)
        """

        # get vmlinux module from context in order to build objects and read symbols
        vmlinux = self.context.modules[symbol_table_name]

        # get kernel layer from context so that it's dependencies can be found, and therefore scanned.
        # kernel layer will be virtual and built ontop of a physical layer.
        kernel_layer = self.context.layers[vmlinux.layer_name]

        # detmine if kernel is 64bit or not. The plugin scans for pointers and these need to formated
        # to the correct size so that they can be accurately located in the physical layer.
        if symbols.symbol_table_is_64bit(self.context, vmlinux.symbol_table_name):
            pack_format = "Q"  # 64 bit
        else:
            pack_format = "I"  # 32 bit

        # TODO: Update plugin to support multiple dependencies. e.g. a memory layer and swap file.
        # This is a shared problem with psscan and having a generic solution would be useful.
        # Find the memory layer to scan, and provide warnings if more than one is located.
        if len(kernel_layer.dependencies) > 1:
            vollog.warning(
                f"Kernel layer depends on multiple layers however only {kernel_layer.dependencies[0]} will be scanned by this plugin."
            )
        elif len(kernel_layer.dependencies) == 0:
            vollog.error(
                f"Kernel layer has no dependencies, meaning there is no memory layer for this plugin to scan."
            )
            raise exceptions.LayerException(
                vmlinux.layer_name, f"Layer {vmlinux.layer_name} has no dependencies"
            )
        memory_layer_name = kernel_layer.dependencies[0]
        memory_layer = self.context.layers[kernel_layer.dependencies[0]]

        # use the init process to build a sock handler
        # TODO: look into options so that sockstat.SockHandlers so that process_sock can
        # be used  without a task object.
        init_task = vmlinux.object_from_symbol(symbol_name="init_task")
        sock_handler = sockstat.SockHandlers(vmlinux, init_task)

        # set to track seen sockets so that results are not duplicated between methods
        sock_physical_addresses = set()

        # get progress_callback in order to use this in the scanners.
        # TODO: perhaps add more detail to progress, showing method in progress and number of hits found
        progress_callback = self._progress_callback

        # TODO: update scanning logic so that all needles can be scanned for at the same time
        # this would allow the results to be shown as the scanning is happening and would
        # make the plugin faster. It would require working out which needle caused the match
        # and applying the logic at that point to get to the socket.

        # Method 1 - find sockets by file operations, then follow pointers to sockets
        file_ops_symbol_names = ["socket_file_ops", "sockfs_dentry_operations"]
        file_ops_needles = []
        for symbol_name in file_ops_symbol_names:

            # TODO: handle cases where symbol is not found
            needle_addr = vmlinux.object_from_symbol(symbol_name).vol.offset
            # use canonicalize to set the appropriate sign extension for the addr
            addr = kernel_layer.canonicalize(needle_addr)
            packed_addr = struct.pack(pack_format, addr)
            file_ops_needles.append(packed_addr)
            vollog.log(
                constants.LOGLEVEL_VVVV,
                f"Method 1 will scan for {symbol_name} using the bytes: {packed_addr.hex()}",
            )

        # get file struct to find the offset to the f_op pointer
        # this is so that the file object can be created at the correct offset,
        # the results of the scanner will be for the f_op member within the file
        f_op_offset = vmlinux.get_type("file").members["f_op"][0]

        for addr, _ in memory_layer.scan(
            self.context,
            scanners.MultiStringScanner(file_ops_needles),
            progress_callback,
        ):
            try:
                # create file in the memory_layer, the native layer matches the
                # kernel so that pointers can be followed
                pfile = self.context.object(
                    vmlinux.symbol_table_name + constants.BANG + "file",
                    offset=addr - f_op_offset,
                    layer_name=memory_layer_name,
                    native_layer_name=vmlinux.layer_name,
                )
                dentry = pfile.get_dentry()
                if not dentry:
                    vollog.log(
                        constants.LOGLEVEL_VVVV,
                        f"Skipping file at {hex(addr)} as unable to locate dentry",
                    )
                    continue

                d_inode = dentry.d_inode
                if not d_inode:
                    vollog.log(
                        constants.LOGLEVEL_VVVV,
                        f"Skipping file at {hex(addr)} as unable to locate inode for dentry",
                    )
                    continue

                socket_alloc = linux.LinuxUtilities.container_of(
                    d_inode, "socket_alloc", "vfs_inode", vmlinux
                )
                socket = socket_alloc.socket
                if not (socket and socket.sk):
                    vollog.log(
                        constants.LOGLEVEL_VVVV,
                        f"Skipping file at {hex(addr)} as socket created by LinuxUtilities.container_of is invalid",
                    )
                    continue

                # sucessfully trversed from file to sock, this will exist in the
                # kernel layer, and need to be translated to the memory layer.
                sock = socket.sk.dereference()
                sock_physical_addresses.add(kernel_layer.translate(sock.vol.offset)[0])

            except exceptions.InvalidAddressException as error:
                vollog.log(
                    constants.LOGLEVEL_VVVV,
                    f"Unable to follow file at {hex(addr)} to socket due to invalid address: {error}",
                )

        # Method 2 - find sockets by socket destructor directly inside sock objects
        socket_destructor_symbol_names = [
            "sock_def_destruct",
            "packet_sock_destruct",
            "unix_sock_destructor",
            "netlink_sock_destruct",
            "inet_sock_destruct",
        ]

        socket_destructor_needles = []
        for socket_destructor_symbol_name in socket_destructor_symbol_names:
            addr = kernel_layer.canonicalize(
                vmlinux.get_symbol(socket_destructor_symbol_name).address
                + vmlinux.offset
            )
            packed_addr = struct.pack(pack_format, addr)
            socket_destructor_needles.append(packed_addr)
            vollog.log(
                constants.LOGLEVEL_VVVV,
                f"Method 2 will scan for {socket_destructor_symbol_name} using the bytes: {packed_addr.hex()}",
            )

        # get sock struct to find the offset to the sk_destruct pointer
        # this is so that the sock object can be created at the correct offset,
        # the results of the scanner will be for the sk_destruct member within the scock
        sk_destruct_offset = vmlinux.get_type("sock").members["sk_destruct"][0]

        for addr, _ in memory_layer.scan(
            self.context,
            scanners.MultiStringScanner(socket_destructor_needles),
            progress_callback,
        ):
            sock_physical_addresses.add(addr - sk_destruct_offset)

        # TODO Method 3 - find sock by sk_error_report symbols
        # sk_error_report_symbol_names = ['sock_def_error_report', 'inet_sk_rebuild_header', 'inet_listen']
        # this would be similar to Method 2, but using a different pointer within sock.

        # now that the set of results has been created, process them and display the results
        for addr in sorted(sock_physical_addresses):
            psock = self.context.object(
                vmlinux.symbol_table_name + constants.BANG + "sock",
                offset=addr,
                layer_name=memory_layer_name,
                native_layer_name=vmlinux.layer_name,
            )
            try:
                sock_type = psock.get_type()

                family = psock.get_family()
                # remove results with no family
                if family == None:
                    vollog.log(
                        constants.LOGLEVEL_VVVV,
                        f"Skipping socket at {hex(addr)} as unable to determin family.",
                    )
                    continue

                # TODO: invesitgate options for more invalid address handling in proccess_sock
                # and the later formatting on it's results.
                sock_fields = sock_handler.process_sock(psock)
                # if no sock_fields we're able to be extracted then skip this result.
                if not sock_fields:
                    vollog.log(
                        constants.LOGLEVEL_VVVV,
                        f"Skipping socket at {hex(addr)} as unable to process with SockHandlers.",
                    )
                    continue

                sock, sock_stat, extended = sock_fields
                src, src_port, dst, dst_port, state = sock_stat
                protocol = sock.get_protocol()

                # format results
                src = NotAvailableValue() if src is None else str(src)
                src_port = NotAvailableValue() if src_port is None else str(src_port)
                dst = NotAvailableValue() if dst is None else str(dst)
                dst_port = NotAvailableValue() if dst_port is None else str(dst_port)
                state = NotAvailableValue() if state is None else str(state)
                protocol = NotAvailableValue() if protocol is None else str(protocol)
                # extended attributes is a dict, so this is formated to string show each
                # key and value pair, seperated with a comma.
                socket_filter_str = (
                    ",".join(f"{k}={v}" for k, v in extended.items())
                    if extended
                    else NotAvailableValue()
                )

                # remove empty results
                if (src == "0.0.0.0" or isinstance(src, NotAvailableValue)) and (
                    dst == "0.0.0.0" or isinstance(src, NotAvailableValue)
                ):
                    if state == "UNCONNECTED":
                        continue
                    elif src_port == "0" and dst_port == "0":
                        continue

                fields = (
                    format_hints.Hex(sock.vol.offset),
                    family,
                    sock_type,
                    protocol,
                    src,
                    src_port,
                    dst,
                    dst_port,
                    state,
                    socket_filter_str,
                )

                yield (0, fields)
            except exceptions.InvalidAddressException as error:
                vollog.log(
                    constants.LOGLEVEL_VVVV,
                    f"Unable create results for socket at {hex(addr)} to invalid address: {error}",
                )

    def run(self):

        tree_grid_args = [
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

        return TreeGrid(
            tree_grid_args,
            self._generator(self.config["kernel"]),
        )
