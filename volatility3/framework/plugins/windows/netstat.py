# This file is Copyright 2020 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

import datetime
import logging
from typing import Iterable, Optional, Generator, Tuple

from volatility3.framework import constants, exceptions, interfaces, renderers, symbols
from volatility3.framework.configuration import requirements
from volatility3.framework.renderers import format_hints
from volatility3.framework.symbols.windows import pdbutil
from volatility3.framework.symbols.windows.extensions import network
from volatility3.plugins import timeliner
from volatility3.plugins.windows import netscan, modules, info, verinfo

vollog = logging.getLogger(__name__)


class NetStat(interfaces.plugins.PluginInterface, timeliner.TimeLinerInterface):
    """Traverses network tracking structures present in a particular windows memory image."""

    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 0)

    @classmethod
    def get_requirements(cls):
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Windows kernel",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.VersionRequirement(
                name="netscan", component=netscan.NetScan, version=(1, 0, 0)
            ),
            requirements.VersionRequirement(
                name="modules", component=modules.Modules, version=(2, 0, 0)
            ),
            requirements.VersionRequirement(
                name="pdbutil", component=pdbutil.PDBUtility, version=(1, 0, 0)
            ),
            requirements.VersionRequirement(
                name="info", component=info.Info, version=(1, 0, 0)
            ),
            requirements.VersionRequirement(
                name="verinfo", component=verinfo.VerInfo, version=(1, 0, 0)
            ),
            requirements.BooleanRequirement(
                name="include-corrupt",
                description="Radically eases result validation. This will show partially overwritten data. WARNING: the results are likely to include garbage and/or corrupt data. Be cautious!",
                default=False,
                optional=True,
            ),
        ]

    @classmethod
    def _decode_pointer(cls, value):
        """Copied from `windows.handles`.

        Windows encodes pointers to objects and decodes them on the fly
        before using them.

        This function mimics the decoding routine so we can generate the
        proper pointer values as well.
        """

        value = value & 0xFFFFFFFFFFFFFFFC

        return value

    @classmethod
    def read_pointer(
        cls,
        context: interfaces.context.ContextInterface,
        layer_name: str,
        offset: int,
        length: int,
    ) -> int:
        """Reads a pointer at a given offset and returns the address it points to.

        Args:
            context: The context to retrieve required elements (layers, symbol tables) from
            layer_name: The name of the layer on which to operate
            offset: Offset of pointer
            length: Pointer length

        Returns:
            The value the pointer points to.
        """

        return int.from_bytes(context.layers[layer_name].read(offset, length), "little")

    @classmethod
    def parse_bitmap(
        cls,
        context: interfaces.context.ContextInterface,
        layer_name: str,
        bitmap_offset: int,
        bitmap_size_in_byte: int,
    ) -> list:
        """Parses a given bitmap and looks for each occurrence of a 1.

        Args:
            context: The context to retrieve required elements (layers, symbol tables) from
            layer_name: The name of the layer on which to operate
            bitmap_offset: Start address of bitmap
            bitmap_size_in_byte: Bitmap size in Byte, not in bit.

        Returns:
            The list of indices at which a 1 was found.
        """
        ret = []
        for idx in range(bitmap_size_in_byte):
            current_byte = context.layers[layer_name].read(bitmap_offset + idx, 1)[0]
            current_offs = idx * 8
            for bit in range(8):
                if current_byte & (1 << bit) != 0:
                    ret.append(bit + current_offs)
        return ret

    @classmethod
    def enumerate_structures_by_port(
        cls,
        context: interfaces.context.ContextInterface,
        layer_name: str,
        net_symbol_table: str,
        port: int,
        port_pool_addr: int,
        proto="tcp",
    ) -> Iterable[interfaces.objects.ObjectInterface]:
        """Lists all UDP Endpoints and TCP Listeners by parsing UdpPortPool and TcpPortPool.

        Args:
            context: The context to retrieve required elements (layers, symbol tables) from
            layer_name: The name of the layer on which to operate
            net_symbol_table: The name of the table containing the tcpip types
            port: Current port as integer to lookup the associated object.
            port_pool_addr: Address of port pool object
            proto: Either "tcp" or "udp" to decide which types to use.

        Returns:
            The list of network objects from this image's TCP and UDP `PortPools`
        """
        if proto == "tcp":
            obj_name = net_symbol_table + constants.BANG + "_TCP_LISTENER"
            ptr_offset = context.symbol_space.get_type(obj_name).relative_child_offset(
                "Next"
            )
        elif proto == "udp":
            obj_name = net_symbol_table + constants.BANG + "_UDP_ENDPOINT"
            ptr_offset = context.symbol_space.get_type(obj_name).relative_child_offset(
                "Next"
            )
        else:
            # invalid argument.
            return None

        vollog.debug(f"Current Port: {port}")
        # the given port serves as a shifted index into the port pool lists
        list_index = port >> 8
        truncated_port = port & 0xFF

        # constructing port_pool object here so callers don't have to
        port_pool = context.object(
            net_symbol_table + constants.BANG + "_INET_PORT_POOL",
            layer_name=layer_name,
            offset=port_pool_addr,
        )

        # first, grab the given port's PortAssignment (`_PORT_ASSIGNMENT`)
        inpa = port_pool.PortAssignments[list_index]

        # then parse the port assignment list (`_PORT_ASSIGNMENT_LIST`) and grab the correct entry
        assignment = inpa.InPaBigPoolBase.Assignments[truncated_port]

        if not assignment:
            return None

        # the value within assignment.Entry is a) masked and b) points inside of the network object
        # first decode the pointer
        netw_inside = cls._decode_pointer(assignment.Entry)

        if netw_inside:
            # if the value is valid, calculate the actual object address by subtracting the offset
            curr_obj = context.object(
                obj_name, layer_name=layer_name, offset=netw_inside - ptr_offset
            )
            yield curr_obj

            # if the same port is used on different interfaces multiple objects are created
            # those can be found by following the pointer within the object's `Next` field until it is empty
            while curr_obj.Next:
                curr_obj = context.object(
                    obj_name,
                    layer_name=layer_name,
                    offset=cls._decode_pointer(curr_obj.Next) - ptr_offset,
                )
                yield curr_obj

    @classmethod
    def get_tcpip_module(
        cls,
        context: interfaces.context.ContextInterface,
        layer_name: str,
        nt_symbols: str,
    ) -> Optional[interfaces.objects.ObjectInterface]:
        """Uses `windows.modules` to find tcpip.sys in memory.

        Args:
            context: The context to retrieve required elements (layers, symbol tables) from
            layer_name: The name of the layer on which to operate
            nt_symbols: The name of the table containing the kernel symbols

        Returns:
            The constructed tcpip.sys module object.
        """
        for mod in modules.Modules.list_modules(context, layer_name, nt_symbols):
            if mod.BaseDllName.get_string() == "tcpip.sys":
                vollog.debug(f"Found tcpip.sys image base @ 0x{mod.DllBase:x}")
                return mod
        return None

    @classmethod
    def parse_hashtable(
        cls,
        context: interfaces.context.ContextInterface,
        layer_name: str,
        ht_offset: int,
        ht_length: int,
        alignment: int,
        net_symbol_table: str,
    ) -> Generator[interfaces.objects.ObjectInterface, None, None]:
        """Parses a hashtable quick and dirty.

        Args:
            context: The context to retrieve required elements (layers, symbol tables) from
            layer_name: The name of the layer on which to operate
            ht_offset: Beginning of the hash table
            ht_length: Length of the hash table

        Returns:
            The hash table entries which are _not_ empty
        """
        # we are looking for entries whose values are not their own address
        for index in range(ht_length):
            current_addr = ht_offset + index * alignment
            current_pointer = context.object(
                net_symbol_table + constants.BANG + "pointer",
                layer_name=layer_name,
                offset=current_addr,
            )
            # check if addr of pointer is equal to the value pointed to
            if current_pointer.vol.offset == current_pointer:
                continue
            yield current_pointer

    @classmethod
    def parse_partitions(
        cls,
        context: interfaces.context.ContextInterface,
        layer_name: str,
        net_symbol_table: str,
        tcpip_symbol_table: str,
        tcpip_module_offset: int,
    ) -> Iterable[interfaces.objects.ObjectInterface]:
        """Parses tcpip.sys's PartitionTable containing established TCP connections.
        The amount of Partition depends on the value of the symbol `PartitionCount` and correlates with
        the maximum processor count (refer to Art of Memory Forensics, chapter 11).

        Args:
            context: The context to retrieve required elements (layers, symbol tables) from
            layer_name: The name of the layer on which to operate
            net_symbol_table: The name of the table containing the tcpip types
            tcpip_symbol_table: The name of the table containing the tcpip driver symbols
            tcpip_module_offset: The offset of the tcpip module

        Returns:
            The list of TCP endpoint objects from the `layer_name` layer's `PartitionTable`
        """
        if symbols.symbol_table_is_64bit(context, net_symbol_table):
            alignment = 0x10
        else:
            alignment = 8

        obj_name = net_symbol_table + constants.BANG + "_TCP_ENDPOINT"
        # part_table_symbol is the offset within tcpip.sys which contains the address of the partition table itself
        part_table_symbol = context.symbol_space.get_symbol(
            tcpip_symbol_table + constants.BANG + "PartitionTable"
        ).address
        part_count_symbol = context.symbol_space.get_symbol(
            tcpip_symbol_table + constants.BANG + "PartitionCount"
        ).address

        part_table_addr = context.object(
            net_symbol_table + constants.BANG + "pointer",
            layer_name=layer_name,
            offset=tcpip_module_offset + part_table_symbol,
        )

        # part_table is the actual partition table offset and consists out of a dynamic amount of _PARTITION objects
        part_table = context.object(
            net_symbol_table + constants.BANG + "_PARTITION_TABLE",
            layer_name=layer_name,
            offset=part_table_addr,
        )
        part_count = int.from_bytes(
            context.layers[layer_name].read(tcpip_module_offset + part_count_symbol, 1),
            "little",
        )
        part_table.Partitions.count = part_count

        vollog.debug(
            "Found TCP connection PartitionTable @ 0x{:x} (partition count: {})".format(
                part_table_addr, part_count
            )
        )
        entry_offset = context.symbol_space.get_type(obj_name).relative_child_offset(
            "ListEntry"
        )
        for ctr, partition in enumerate(part_table.Partitions):
            vollog.debug(f"Parsing partition {ctr}")
            if partition.Endpoints.NumEntries > 0:
                for endpoint_entry in cls.parse_hashtable(
                    context,
                    layer_name,
                    partition.Endpoints.Directory,
                    partition.Endpoints.TableSize,
                    alignment,
                    net_symbol_table,
                ):
                    endpoint = context.object(
                        obj_name,
                        layer_name=layer_name,
                        offset=endpoint_entry - entry_offset,
                    )
                    yield endpoint

    @classmethod
    def create_tcpip_symbol_table(
        cls,
        context: interfaces.context.ContextInterface,
        config_path: str,
        layer_name: str,
        tcpip_module_offset: int,
        tcpip_module_size: int,
    ) -> str:
        """DEPRECATED: Use PDBUtility.symbol_table_from_pdb instead

        Creates symbol table for the current image's tcpip.sys driver.

        Searches the memory section of the loaded tcpip.sys module for its PDB GUID
        and loads the associated symbol table into the symbol space.

        Args:
            context: The context to retrieve required elements (layers, symbol tables) from
            config_path: The config path where to find symbol files
            layer_name: The name of the layer on which to operate
            tcpip_module_offset: This memory dump's tcpip.sys image offset
            tcpip_module_size: The size of `tcpip.sys` for this dump

        Returns:
            The name of the constructed and loaded symbol table
        """
        vollog.debug(
            "Deprecation: This plugin uses netstat.create_tcpip_symbol_table instead of PDBUtility.symbol_table_from_pdb"
        )
        return pdbutil.PDBUtility.symbol_table_from_pdb(
            context,
            interfaces.configuration.path_join(config_path, "tcpip"),
            layer_name,
            "tcpip.pdb",
            tcpip_module_offset,
            tcpip_module_size,
        )

    @classmethod
    def find_port_pools(
        cls,
        context: interfaces.context.ContextInterface,
        layer_name: str,
        net_symbol_table: str,
        tcpip_symbol_table: str,
        tcpip_module_offset: int,
    ) -> Tuple[int, int]:
        """Finds the given image's port pools. Older Windows versions (presumably < Win10 build 14251) use driver
        symbols called `UdpPortPool` and `TcpPortPool` which point towards the pools.
        Newer Windows versions use `UdpCompartmentSet` and `TcpCompartmentSet`, which we first have to translate into
        the port pool address. See also: http://redplait.blogspot.com/2016/06/tcpip-port-pools-in-fresh-windows-10.html

        Args:
            context: The context to retrieve required elements (layers, symbol tables) from
            layer_name: The name of the layer on which to operate
            net_symbol_table: The name of the table containing the tcpip types
            tcpip_module_offset: This memory dump's tcpip.sys image offset
            tcpip_symbol_table: The name of the table containing the tcpip driver symbols

        Returns:
            The tuple containing the address of the UDP and TCP port pool respectively.
        """

        if "UdpPortPool" in context.symbol_space[tcpip_symbol_table].symbols:
            # older Windows versions
            upp_symbol = context.symbol_space.get_symbol(
                tcpip_symbol_table + constants.BANG + "UdpPortPool"
            ).address
            upp_addr = context.object(
                net_symbol_table + constants.BANG + "pointer",
                layer_name=layer_name,
                offset=tcpip_module_offset + upp_symbol,
            )

            tpp_symbol = context.symbol_space.get_symbol(
                tcpip_symbol_table + constants.BANG + "TcpPortPool"
            ).address
            tpp_addr = context.object(
                net_symbol_table + constants.BANG + "pointer",
                layer_name=layer_name,
                offset=tcpip_module_offset + tpp_symbol,
            )

        elif "UdpCompartmentSet" in context.symbol_space[tcpip_symbol_table].symbols:
            # newer Windows versions since 10.14xxx
            ucs = context.symbol_space.get_symbol(
                tcpip_symbol_table + constants.BANG + "UdpCompartmentSet"
            ).address
            tcs = context.symbol_space.get_symbol(
                tcpip_symbol_table + constants.BANG + "TcpCompartmentSet"
            ).address

            ucs_offset = context.object(
                net_symbol_table + constants.BANG + "pointer",
                layer_name=layer_name,
                offset=tcpip_module_offset + ucs,
            )
            tcs_offset = context.object(
                net_symbol_table + constants.BANG + "pointer",
                layer_name=layer_name,
                offset=tcpip_module_offset + tcs,
            )

            ucs_obj = context.object(
                net_symbol_table + constants.BANG + "_INET_COMPARTMENT_SET",
                layer_name=layer_name,
                offset=ucs_offset,
            )
            upp_addr = ucs_obj.InetCompartment.ProtocolCompartment.PortPool

            tcs_obj = context.object(
                net_symbol_table + constants.BANG + "_INET_COMPARTMENT_SET",
                layer_name=layer_name,
                offset=tcs_offset,
            )
            tpp_addr = tcs_obj.InetCompartment.ProtocolCompartment.PortPool

        else:
            # this branch should not be reached.
            raise exceptions.SymbolError(
                "UdpPortPool",
                tcpip_symbol_table,
                f"Neither UdpPortPool nor UdpCompartmentSet found in {tcpip_symbol_table} table",
            )

        vollog.debug(f"Found PortPools @ 0x{upp_addr:x} (UDP) && 0x{tpp_addr:x} (TCP)")
        return upp_addr, tpp_addr

    @classmethod
    def list_sockets(
        cls,
        context: interfaces.context.ContextInterface,
        layer_name: str,
        nt_symbols: str,
        net_symbol_table: str,
        tcpip_module_offset: int,
        tcpip_symbol_table: str,
    ) -> Iterable[interfaces.objects.ObjectInterface]:
        """Lists all UDP Endpoints, TCP Listeners and TCP Endpoints in the primary layer that
        are in tcpip.sys's UdpPortPool, TcpPortPool and TCP Endpoint partition table, respectively.

        Args:
            context: The context to retrieve required elements (layers, symbol tables) from
            layer_name: The name of the layer on which to operate
            nt_symbols: The name of the table containing the kernel symbols
            net_symbol_table: The name of the table containing the tcpip types
            tcpip_module_offset: Offset of `tcpip.sys`'s PE image in memory
            tcpip_symbol_table: The name of the table containing the tcpip driver symbols

        Returns:
            The list of network objects from the `layer_name` layer's `PartitionTable` and `PortPools`
        """

        # first, TCP endpoints by parsing the partition table
        for endpoint in cls.parse_partitions(
            context,
            layer_name,
            net_symbol_table,
            tcpip_symbol_table,
            tcpip_module_offset,
        ):
            yield endpoint

        # then, towards the UDP and TCP port pools
        # first, find their addresses
        upp_addr, tpp_addr = cls.find_port_pools(
            context,
            layer_name,
            net_symbol_table,
            tcpip_symbol_table,
            tcpip_module_offset,
        )

        # create port pool objects at the detected address and parse the port bitmap
        upp_obj = context.object(
            net_symbol_table + constants.BANG + "_INET_PORT_POOL",
            layer_name=layer_name,
            offset=upp_addr,
        )
        udpa_ports = cls.parse_bitmap(
            context,
            layer_name,
            upp_obj.PortBitMap.Buffer,
            upp_obj.PortBitMap.SizeOfBitMap // 8,
        )

        tpp_obj = context.object(
            net_symbol_table + constants.BANG + "_INET_PORT_POOL",
            layer_name=layer_name,
            offset=tpp_addr,
        )
        tcpl_ports = cls.parse_bitmap(
            context,
            layer_name,
            tpp_obj.PortBitMap.Buffer,
            tpp_obj.PortBitMap.SizeOfBitMap // 8,
        )

        vollog.debug(f"Found TCP Ports: {tcpl_ports}")
        vollog.debug(f"Found UDP Ports: {udpa_ports}")
        # given the list of TCP / UDP ports, calculate the address of their respective objects and yield them.
        for port in tcpl_ports:
            # port value can be 0, which we can skip
            if not port:
                continue
            for obj in cls.enumerate_structures_by_port(
                context, layer_name, net_symbol_table, port, tpp_addr, "tcp"
            ):
                yield obj

        for port in udpa_ports:
            # same as above, skip port 0
            if not port:
                continue
            for obj in cls.enumerate_structures_by_port(
                context, layer_name, net_symbol_table, port, upp_addr, "udp"
            ):
                yield obj

    def _generator(self, show_corrupt_results: Optional[bool] = None):
        """Generates the network objects for use in rendering."""

        kernel = self.context.modules[self.config["kernel"]]

        netscan_symbol_table = netscan.NetScan.create_netscan_symbol_table(
            self.context, kernel.layer_name, kernel.symbol_table_name, self.config_path
        )

        tcpip_module = self.get_tcpip_module(
            self.context, kernel.layer_name, kernel.symbol_table_name
        )
        if not tcpip_module:
            vollog.error("Unable to locate symbols for the memory image's tcpip module")

        try:
            tcpip_symbol_table = pdbutil.PDBUtility.symbol_table_from_pdb(
                self.context,
                interfaces.configuration.path_join(self.config_path, "tcpip"),
                kernel.layer_name,
                "tcpip.pdb",
                tcpip_module.DllBase,
                tcpip_module.SizeOfImage,
            )
        except exceptions.VolatilityException:
            vollog.error("Unable to locate symbols for the memory image's tcpip module")

        for netw_obj in self.list_sockets(
            self.context,
            kernel.layer_name,
            kernel.symbol_table_name,
            netscan_symbol_table,
            tcpip_module.DllBase,
            tcpip_symbol_table,
        ):
            # objects passed pool header constraints. check for additional constraints if strict flag is set.
            if not show_corrupt_results and not netw_obj.is_valid():
                continue

            if isinstance(netw_obj, network._UDP_ENDPOINT):
                vollog.debug(f"Found UDP_ENDPOINT @ 0x{netw_obj.vol.offset:2x}")

                # For UdpA, the state is always blank and the remote end is asterisks
                for ver, laddr, _ in netw_obj.dual_stack_sockets():
                    yield (
                        0,
                        (
                            format_hints.Hex(netw_obj.vol.offset),
                            "UDP" + ver,
                            laddr,
                            netw_obj.Port,
                            "*",
                            0,
                            "",
                            netw_obj.get_owner_pid() or renderers.UnreadableValue(),
                            netw_obj.get_owner_procname()
                            or renderers.UnreadableValue(),
                            netw_obj.get_create_time() or renderers.UnreadableValue(),
                        ),
                    )

            elif isinstance(netw_obj, network._TCP_ENDPOINT):
                vollog.debug(f"Found _TCP_ENDPOINT @ 0x{netw_obj.vol.offset:2x}")
                if netw_obj.get_address_family() == network.AF_INET:
                    proto = "TCPv4"
                elif netw_obj.get_address_family() == network.AF_INET6:
                    proto = "TCPv6"
                else:
                    vollog.debug(
                        "TCP Endpoint @ 0x{:2x} has unknown address family 0x{:x}".format(
                            netw_obj.vol.offset, netw_obj.get_address_family()
                        )
                    )
                    proto = "TCPv?"

                try:
                    state = netw_obj.State.description
                except ValueError:
                    state = renderers.UnreadableValue()

                yield (
                    0,
                    (
                        format_hints.Hex(netw_obj.vol.offset),
                        proto,
                        netw_obj.get_local_address() or renderers.UnreadableValue(),
                        netw_obj.LocalPort,
                        netw_obj.get_remote_address() or renderers.UnreadableValue(),
                        netw_obj.RemotePort,
                        state,
                        netw_obj.get_owner_pid() or renderers.UnreadableValue(),
                        netw_obj.get_owner_procname() or renderers.UnreadableValue(),
                        netw_obj.get_create_time() or renderers.UnreadableValue(),
                    ),
                )

            # check for isinstance of tcp listener last, because all other objects are inherited from here
            elif isinstance(netw_obj, network._TCP_LISTENER):
                vollog.debug(f"Found _TCP_LISTENER @ 0x{netw_obj.vol.offset:2x}")

                # For TcpL, the state is always listening and the remote port is zero
                for ver, laddr, raddr in netw_obj.dual_stack_sockets():
                    yield (
                        0,
                        (
                            format_hints.Hex(netw_obj.vol.offset),
                            "TCP" + ver,
                            laddr,
                            netw_obj.Port,
                            raddr,
                            0,
                            "LISTENING",
                            netw_obj.get_owner_pid() or renderers.UnreadableValue(),
                            netw_obj.get_owner_procname()
                            or renderers.UnreadableValue(),
                            netw_obj.get_create_time() or renderers.UnreadableValue(),
                        ),
                    )
            else:
                # this should not happen therefore we log it.
                vollog.debug(
                    f"Found network object unsure of its type: {netw_obj} of type {type(netw_obj)}"
                )

    def generate_timeline(self):
        for row in self._generator():
            _depth, row_data = row
            row_dict = {}
            (
                row_dict["Offset"],
                row_dict["Proto"],
                row_dict["LocalAddr"],
                row_dict["LocalPort"],
                row_dict["ForeignAddr"],
                row_dict["ForeignPort"],
                row_dict["State"],
                row_dict["PID"],
                row_dict["Owner"],
                row_dict["Created"],
            ) = row_data

            # Skip network connections without creation time
            if not isinstance(row_dict["Created"], datetime.datetime):
                continue
            description = (
                "Network connection: Process {} {} Local Address {}:{} "
                "Remote Address {}:{} State {} Protocol {} ".format(
                    row_dict["PID"],
                    row_dict["Owner"],
                    row_dict["LocalAddr"],
                    row_dict["LocalPort"],
                    row_dict["ForeignAddr"],
                    row_dict["ForeignPort"],
                    row_dict["State"],
                    row_dict["Proto"],
                )
            )

            yield (description, timeliner.TimeLinerType.CREATED, row_dict["Created"])

    def run(self):
        show_corrupt_results = self.config.get("include-corrupt", None)

        return renderers.TreeGrid(
            [
                ("Offset", format_hints.Hex),
                ("Proto", str),
                ("LocalAddr", str),
                ("LocalPort", int),
                ("ForeignAddr", str),
                ("ForeignPort", int),
                ("State", str),
                ("PID", int),
                ("Owner", str),
                ("Created", datetime.datetime),
            ],
            self._generator(show_corrupt_results=show_corrupt_results),
        )
