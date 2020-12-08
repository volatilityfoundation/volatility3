# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

import logging
import datetime
from typing import Iterable, List, Optional, Callable

from volatility.framework import constants, exceptions, interfaces, renderers, symbols, layers
from volatility.framework.configuration import requirements
from volatility.framework.renderers import format_hints
from volatility.framework.symbols import intermed
from volatility.framework.symbols.windows.extensions import network
from volatility.framework.symbols.windows.pdbutil import PDBUtility
from volatility.plugins import timeliner
from volatility.plugins.windows import info, poolscanner, netscan, modules

vollog = logging.getLogger(__name__)


class NetList(interfaces.plugins.PluginInterface, timeliner.TimeLinerInterface):
    """Scans for network objects present in a particular windows memory image."""

    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 0)

    @classmethod
    def get_requirements(cls):
        return [
            requirements.TranslationLayerRequirement(name = 'primary',
                                                     description = 'Memory layer for the kernel',
                                                     architectures = ["Intel32", "Intel64"]),
            requirements.SymbolTableRequirement(name = "nt_symbols", description = "Windows kernel symbols"),
            requirements.VersionRequirement(name = 'netscan', component = netscan.NetScan, version = (1, 0, 0)),
            requirements.BooleanRequirement(
                name = 'include-corrupt',
                description =
                "Radically eases result validation. This will show partially overwritten data. WARNING: the results are likely to include garbage and/or corrupt data. Be cautious!",
                default = False,
                optional = True),
        ]

    @classmethod
    def _decode_pointer(self, value):
        """Windows encodes pointers to objects and decodes them on the fly
        before using them.

        This function mimics the decoding routine so we can generate the
        proper pointer values as well.
        """

        value = value & 0xFFFFFFFFFFFFFFFC

        return value

    @classmethod
    def read_pointer(cls,
                     context: interfaces.context.ContextInterface,
                     layer_name: str,
                     offset: int,
                     length: int) -> int:

        return int.from_bytes(context.layers[layer_name].read(offset, length), "little")

    @classmethod
    def parse_bitmap(cls,
                     context: interfaces.context.ContextInterface,
                     layer_name: str,
                     bitmap_offset: int,
                     bitmap_size_in_byte: int) -> list:
        ret = []
        for idx in range(bitmap_size_in_byte-1):
            current_byte = context.layers[layer_name].read(bitmap_offset + idx, 1)[0]
            current_offs = idx*8
            if current_byte&1 != 0:
                ret.append(0 + current_offs)
            if current_byte&2 != 0:
                ret.append(1 + current_offs)
            if current_byte&4 != 0:
                ret.append(2 + current_offs)
            if current_byte&8 != 0:
                ret.append(3 + current_offs)
            if current_byte&16 != 0:
                ret.append(4 + current_offs)
            if current_byte&32 != 0:
                ret.append(5 + current_offs)
            if current_byte&64 != 0:
                ret.append(6 + current_offs)
            if current_byte&128 != 0:
                ret.append(7 + current_offs)
        return ret

    @classmethod
    def enumerate_structures_by_port(cls,
                       context: interfaces.context.ContextInterface,
                       layer_name: str,
                       net_symbol_table: str,
                       port: int,
                       ppobj,
                       proto="tcp"):
        if proto == "tcp":
            obj_name = net_symbol_table + constants.BANG + "_TCP_LISTENER"
            ptr_offset = context.symbol_space.get_type(obj_name).relative_child_offset("Next")
        elif proto == "udp":
            obj_name = net_symbol_table + constants.BANG + "_UDP_ENDPOINT"
            ptr_offset = context.symbol_space.get_type(obj_name).relative_child_offset("Next")
        else:
            yield
        list_index = port >> 8
        truncated_port = port & 0xff
        inpa = ppobj.PortAssignments[list_index].dereference()
        assignment = inpa.InPaBigPoolBase.dereference().Assignments[truncated_port]
        if not assignment:
            yield
        netw_inside = cls._decode_pointer(assignment.Entry)
        if netw_inside:
            curr_obj = context.object(obj_name, layer_name = layer_name, offset = netw_inside - ptr_offset)
            vollog.debug("Found object @ 0x{:2x}, yielding...".format(curr_obj.vol.offset))
            yield curr_obj

            vollog.debug("PrevPointer val: {}".format(curr_obj.Next))
            while curr_obj.Next:
                curr_obj = context.object(obj_name, layer_name = layer_name, offset = cls._decode_pointer(curr_obj.Next) - ptr_offset)
                yield curr_obj
                vollog.debug("Checking if PrevPointer is valid (val: {})".format(curr_obj.Next))

    @classmethod
    def get_tcpip_module(cls, context, layer_name, nt_symbols):
        for mod in modules.Modules.list_modules(context, layer_name, nt_symbols):
            # ~ print(mod.BaseDllName.get_string())
            if mod.BaseDllName.get_string() == "tcpip.sys":
                vollog.debug("Found tcpip.sys offset @ 0x{:x}".format(mod.DllBase))
                return mod

    @classmethod
    def get_tcpip_guid(cls, context, layer_name, tcpip_module):
        return list(
            PDBUtility.pdbname_scan(
                context,
                layer_name,
                context.layers[layer_name].page_size,
                [b"tcpip.pdb"],
                start=tcpip_module.DllBase,
                end=tcpip_module.DllBase + tcpip_module.SizeOfImage
            )
        )

    @classmethod
    def parse_hashtable(cls, context, layer_name, ht_offset, ht_length, pointer_length) -> list:
        # ~ ret = []
        for idx in range(ht_length):
            current_qword = (0xffff000000000000 | cls.read_pointer(context, layer_name, ht_offset + idx * 16, pointer_length))
            if current_qword == (0xffff000000000000 | (ht_offset + idx * 16)):
                continue
            yield current_qword

    @classmethod
    def parse_partitions(cls, context, layer_name, net_symbol_table, tcpip_symbol_table, tcpip_module_offset, pointer_length):
        # ~ endpoints = []
        obj_name = net_symbol_table + constants.BANG + "_TCP_ENDPOINT"
        pto = context.symbol_space.get_symbol(tcpip_symbol_table + constants.BANG + "PartitionTable").address
        pco = context.symbol_space.get_symbol(tcpip_symbol_table + constants.BANG + "PartitionCount").address
        part_table = cls.read_pointer(context, layer_name, tcpip_module_offset + pto, pointer_length)
        part_count = int.from_bytes(context.layers[layer_name].read(tcpip_module_offset + pco, 1), "little")
        partitions = []
        for part_idx in range(part_count):
            current_partition = context.object(net_symbol_table + "!_PARTITION", layer_name = layer_name, offset = part_table + 128 * part_idx)
            partitions.append(current_partition)
        for partition in partitions:
            if partition.Endpoints.NumEntries > 0:
                for endpoint_entry in cls.parse_hashtable(context, layer_name, partition.Endpoints.Directory, 128, pointer_length):
                    # ~ yield endpoint
                    entry_offset = context.symbol_space.get_type(obj_name).relative_child_offset("HashTableEntry")
                    endpoint = context.object(obj_name, layer_name = layer_name, offset = endpoint_entry - entry_offset)
                    yield endpoint
                # ~ endpoints.extend(parse_hashtable(partition.Endpoints.Directory, 128))
        # ~ return endpoints

    @classmethod
    def create_tcpip_symbol_table(cls,
                                    context: interfaces.context.ContextInterface,
                                    config_path: str,
                                    layer_name: str,
                                    tcpip_module):

        guids = cls.get_tcpip_guid(context, layer_name, tcpip_module)

        if not guids:
            print("no pdb found!")
            raise

        guid = guids[0]

        vollog.debug("Found {}: {}-{}".format(guid["pdb_name"], guid["GUID"], guid["age"]))

        return PDBUtility.load_windows_symbol_table(context,
                                                    guid["GUID"],
                                                    guid["age"],
                                                    guid["pdb_name"],
                                                    "volatility.framework.symbols.intermed.IntermediateSymbolTable",
                                                    config_path="tcpip")

    @classmethod
    def list_sockets(cls,
                       context: interfaces.context.ContextInterface,
                       layer_name: str,
                       nt_symbols,
                       net_symbol_table: str,
                       tcpip_module,
                       tcpip_symbol_table: str) -> \
            Iterable[interfaces.objects.ObjectInterface]:
        """Lists all the processes in the primary layer that are in the pid
        config option.

        Args:
            context: The context to retrieve required elements (layers, symbol tables) from
            layer_name: The name of the layer on which to operate
            nt_symbols: The name of the table containing the kernel symbols
            net_symbol_table: The name of the table containing the tcpip symbols

        Returns:
            The list of network objects from the `layer_name` layer's `PartitionTable` and `PortPools`
        """

        tcpip_vo = tcpip_module.DllBase

        pointer_length = context.symbol_space.get_type(net_symbol_table + constants.BANG + "pointer").size

        # tcpe

        for endpoint in cls.parse_partitions(context, layer_name, net_symbol_table, tcpip_symbol_table, tcpip_vo, pointer_length):
            yield endpoint

        # listeners

        ucs = context.symbol_space.get_symbol(tcpip_symbol_table + constants.BANG + "UdpCompartmentSet").address
        tcs = context.symbol_space.get_symbol(tcpip_symbol_table + constants.BANG + "TcpCompartmentSet").address

        ucs_offset = cls.read_pointer(context, layer_name, tcpip_vo + ucs, pointer_length)
        tcs_offset = cls.read_pointer(context, layer_name, tcpip_vo + tcs, pointer_length)

        ucs_obj = context.object(net_symbol_table + constants.BANG + "_INET_COMPARTMENT_SET", layer_name = layer_name, offset = ucs_offset)
        upp_addr = ucs_obj.InetCompartment.dereference().ProtocolCompartment.dereference().PortPool

        upp_obj = context.object(net_symbol_table + constants.BANG + "_INET_PORT_POOL", layer_name = layer_name, offset = upp_addr)
        udpa_ports = cls.parse_bitmap(context, layer_name, upp_obj.PortBitMap.Buffer, upp_obj.PortBitMap.SizeOfBitMap // 8)

        tcs_obj = context.object(net_symbol_table + constants.BANG + "_INET_COMPARTMENT_SET", layer_name = layer_name, offset = tcs_offset)
        tpp_addr = tcs_obj.InetCompartment.dereference().ProtocolCompartment.dereference().PortPool

        tpp_obj = context.object(net_symbol_table + constants.BANG + "_INET_PORT_POOL", layer_name = layer_name, offset = tpp_addr)
        tcpl_ports = cls.parse_bitmap(context, layer_name, tpp_obj.PortBitMap.Buffer, tpp_obj.PortBitMap.SizeOfBitMap // 8)

        for port in tcpl_ports:
            if port == 0:
                continue
            for obj in cls.enumerate_structures_by_port(context, layer_name, net_symbol_table, port, tpp_obj, "tcp"):
                yield obj

        for port in udpa_ports:
            if port == 0:
                continue
            for obj in cls.enumerate_structures_by_port(context, layer_name, net_symbol_table, port, upp_obj, "udp"):
                yield obj

    def _generator(self, show_corrupt_results: Optional[bool] = None):
        """ Generates the network objects for use in rendering. """

        netscan_symbol_table = netscan.NetScan.create_netscan_symbol_table(self.context, self.config["primary"],
                                                                self.config["nt_symbols"], self.config_path)

        tcpip_module = self.get_tcpip_module(self.context, self.config["primary"], self.config["nt_symbols"])

        tcpip_symbol_table = self.create_tcpip_symbol_table(self.context, self.config_path, self.config["primary"], tcpip_module)

        for netw_obj in self.list_sockets(self.context,
                                            self.config['primary'],
                                            self.config['nt_symbols'],
                                            netscan_symbol_table,
                                            tcpip_module,
                                            tcpip_symbol_table):

            vollog.debug("Found netw obj @ 0x{:2x} of assumed type {}".format(netw_obj.vol.offset, type(netw_obj)))
            # objects passed pool header constraints. check for additional constraints if strict flag is set.
            if not show_corrupt_results and not netw_obj.is_valid():
                continue

            if isinstance(netw_obj, network._UDP_ENDPOINT):
                vollog.debug("Found UDP_ENDPOINT @ 0x{:2x}".format(netw_obj.vol.offset))

                # For UdpA, the state is always blank and the remote end is asterisks
                for ver, laddr, _ in netw_obj.dual_stack_sockets():
                    yield (0, (format_hints.Hex(netw_obj.vol.offset), "UDP" + ver, laddr, netw_obj.Port, "*", 0, "",
                               netw_obj.get_owner_pid() or renderers.UnreadableValue(), netw_obj.get_owner_procname()
                               or renderers.UnreadableValue(), netw_obj.get_create_time()
                               or renderers.UnreadableValue()))

            elif isinstance(netw_obj, network._TCP_ENDPOINT):
                vollog.debug("Found _TCP_ENDPOINT @ 0x{:2x}".format(netw_obj.vol.offset))
                if netw_obj.get_address_family() == network.AF_INET:
                    proto = "TCPv4"
                elif netw_obj.get_address_family() == network.AF_INET6:
                    proto = "TCPv6"
                else:
                    proto = "TCPv?"

                try:
                    state = netw_obj.State.description
                except ValueError:
                    state = renderers.UnreadableValue()

                yield (0, (format_hints.Hex(netw_obj.vol.offset), proto, netw_obj.get_local_address()
                           or renderers.UnreadableValue(), netw_obj.LocalPort, netw_obj.get_remote_address()
                           or renderers.UnreadableValue(), netw_obj.RemotePort, state, netw_obj.get_owner_pid()
                           or renderers.UnreadableValue(), netw_obj.get_owner_procname() or renderers.UnreadableValue(),
                           netw_obj.get_create_time() or renderers.UnreadableValue()))

            # check for isinstance of tcp listener last, because all other objects are inherited from here
            elif isinstance(netw_obj, network._TCP_LISTENER):
                vollog.debug("Found _TCP_LISTENER @ 0x{:2x}".format(netw_obj.vol.offset))

                # For TcpL, the state is always listening and the remote port is zero
                for ver, laddr, raddr in netw_obj.dual_stack_sockets():
                    yield (0, (format_hints.Hex(netw_obj.vol.offset), "TCP" + ver, laddr, netw_obj.Port, raddr, 0,
                               "LISTENING", netw_obj.get_owner_pid() or renderers.UnreadableValue(),
                               netw_obj.get_owner_procname() or renderers.UnreadableValue(), netw_obj.get_create_time()
                               or renderers.UnreadableValue()))
            else:
                # this should not happen therefore we log it.
                vollog.debug("Found network object unsure of its type: {} of type {}".format(netw_obj, type(netw_obj)))

    def generate_timeline(self):
        for row in self._generator():
            _depth, row_data = row
            # Skip network connections without creation time
            if not isinstance(row_data[9], datetime.datetime):
                continue
            row_data = [
                "N/A" if isinstance(i, renderers.UnreadableValue) or isinstance(i, renderers.UnparsableValue) else i
                for i in row_data
            ]
            description = "Network connection: Process {} {} Local Address {}:{} " \
                          "Remote Address {}:{} State {} Protocol {} ".format(row_data[7], row_data[8],
                                                                              row_data[2], row_data[3],
                                                                              row_data[4], row_data[5],
                                                                              row_data[6], row_data[1])
            yield (description, timeliner.TimeLinerType.CREATED, row_data[9])

    def run(self):
        show_corrupt_results = self.config.get('include-corrupt', None)

        return renderers.TreeGrid([
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
        ], self._generator(show_corrupt_results = show_corrupt_results))
