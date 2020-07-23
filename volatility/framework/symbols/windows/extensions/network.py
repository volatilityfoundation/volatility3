# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

import enum
import itertools
import logging
import socket

from volatility.framework import objects, interfaces, exceptions
from volatility.framework import exceptions
from volatility.framework.objects import Array
from volatility.framework.renderers import conversion
from volatility.framework.symbols.wrappers import Flags
from volatility.framework import renderers
from typing import Dict, Tuple

vollog = logging.getLogger(__name__)

def inet_ntop(address_family: int, packed_ip: Array) -> str:

    def inet_ntop4(packed_ip: Array) -> str:

        if not (isinstance(packed_ip, list) or isinstance(packed_ip, Array)):
            raise TypeError("must be Array, not {0}".format(type(packed_ip)))
        if len(packed_ip) != 4:
            raise ValueError("invalid length of packed IP address string")
        return "{0}.{1}.{2}.{3}".format(*[x.to_bytes(1, "little")[0] for x in packed_ip])

    def inet_ntop6(packed_ip) -> str:
        if not (isinstance(packed_ip, list) or isinstance(packed_ip, Array)):
            raise TypeError("must be Array, not {0}".format(type(packed_ip)))

        if len(packed_ip) != 16:
            raise ValueError("invalid length of packed IP address string")

        words = []
        for i in range(0, 16, 2):
            words.append((packed_ip[i] << 8) | packed_ip[i + 1])

        # Replace a run of 0x00s with None
        numlen = [(k, len(list(g))) for k, g in itertools.groupby(words)]
        max_zero_run = sorted(sorted(numlen, key = lambda x: x[1], reverse = True), key = lambda x: x[0])[0]
        words = []
        for k, l in numlen:
            if (k == 0) and (l == max_zero_run[1]) and not (None in words):
                words.append(None)
            else:
                for i in range(l):
                    words.append(k)

        # Handle encapsulated IPv4 addresses
        encapsulated = ""
        if (words[0] is None) and (len(words) == 3 or (len(words) == 4 and words[1] == 0xffff)):
            words = words[:-2]
            encapsulated = inet_ntop4(packed_ip[-4:])
        # If we start or end with None, then add an additional :
        if words[0] is None:
            words = [None] + words
        if words[-1] is None:
            words += [None]
        # Join up everything we've got using :s
        return ":".join(["{0:x}".format(w) if w is not None else "" for w in words]) + encapsulated

    if address_family == socket.AF_INET:
        return inet_ntop4(packed_ip)
    elif address_family == socket.AF_INET6:
        return inet_ntop6(packed_ip)
    raise socket.error("[Errno 97] Address family not supported by protocol")

# Python's socket.AF_INET6 is 0x1e but Microsoft defines it
# as a constant value of 0x17 in their source code. Thus we
# need Microsoft's since that's what is found in memory.
AF_INET = 2
AF_INET6 = 0x17

# String representations of INADDR_ANY and INADDR6_ANY
inaddr_any = inet_ntop(socket.AF_INET, [0] * 4)
inaddr6_any = inet_ntop(socket.AF_INET6, [0] * 16)

# copied to here as symbol space does not appear to support custom Enums
TCP_STATE_ENUM = {
    0: 'CLOSED',
    1: 'LISTENING',
    2: 'SYN_SENT',
    3: 'SYN_RCVD',
    4: 'ESTABLISHED',
    5: 'FIN_WAIT1',
    6: 'FIN_WAIT2',
    7: 'CLOSE_WAIT',
    8: 'CLOSING',
    9: 'LAST_ACK',
    12: 'TIME_WAIT',
    13: 'DELETE_TCB'
}

class _TCP_LISTENER(objects.StructType):
    """Class for objects found in TcpL pools.

    This class serves as a base class for all pooled network objects.

    It exposes some functions which return sanity-checked members. Substructures referred to by a
    pointer may appear valid at first glance but will throw an InvalidAddressException on access.

    This is not a problem when objects are validated via their `is_valid()` method, but when
    scanning for semi-corrupted data this check will not be performed.

    Be mindful that most of those methods return `None` when they would access invalid data.
    If you want to process the raw data access the attributes directly, e.g.
    via `network_object.InetAF` instead of `network_object.get_address_family()`.

    """

    def __init__(self, context: interfaces.context.ContextInterface, type_name: str,
                 object_info: interfaces.objects.ObjectInformation, size: int,
                 members: Dict[str, Tuple[int, interfaces.objects.Template]]) -> None:

        super().__init__(context = context,
                         type_name = type_name,
                         object_info = object_info,
                         size = size,
                         members = members)

    def get_address_family(self):
        try:
            return self.InetAF.dereference().AddressFamily

        except exceptions.InvalidAddressException:
            return None

    def get_owner(self):
        try:
            return self.member('Owner').dereference()

        except exceptions.InvalidAddressException:
            return None

    def get_owner_pid(self):
        try:
            if self.get_owner().is_valid():
                return self.get_owner().UniqueProcessId
            else:
                return None

        except exceptions.InvalidAddressException:
            return None

    def get_owner_procname(self):
        try:
            if self.get_owner().is_valid():
                return self.get_owner().ImageFileName.cast(
                        "string", max_length = self.get_owner().ImageFileName.vol.count, errors = "replace")
            else:
                return None

        except exceptions.InvalidAddressException:
            return None

    def get_create_time(self):
        dt_obj = conversion.wintime_to_datetime(self.CreateTime.QuadPart)

        if isinstance(dt_obj, interfaces.renderers.BaseAbsentValue):
            return dt_obj

        # return None if the timestamp seems invalid
        if dt_obj.year < 1950 or dt_obj.year > 2200:
            return None
        else:
            return dt_obj

    def get_in_addr(self):
        try:
            local_addr = self.LocalAddr.dereference()

            if local_addr.pData.dereference():
                inaddr = local_addr.inaddr
                return inaddr
            else:
                return None

        except exceptions.InvalidAddressException:
            return None

    def dual_stack_sockets(self):
        """Handle Windows dual-stack sockets"""

        # If this pointer is valid, the socket is bound to
        # a specific IP address. Otherwise, the socket is
        # listening on all IP addresses of the address family.

        # Note the remote address is always INADDR_ANY or
        # INADDR6_ANY for sockets. The moment a client
        # connects to the listener, a TCP_ENDPOINT is created
        # and that structure contains the remote address.

        inaddr = self.get_in_addr()

        if inaddr:
            if self.get_address_family() == AF_INET:
                yield "v4", inet_ntop(socket.AF_INET, inaddr.addr4), inaddr_any
            elif self.get_address_family() == AF_INET6:
                yield "v6", inet_ntop(socket.AF_INET6, inaddr.addr6), inaddr6_any
        else:
            yield "v4", inaddr_any, inaddr_any
            if self.get_address_family() == AF_INET6:
                yield "v6", inaddr6_any, inaddr6_any

    def is_valid(self):

        try:
            if not self.get_address_family() in (AF_INET, AF_INET6):
                return False

        except exceptions.InvalidAddressException:
            return False
        return True

class _TCP_ENDPOINT(_TCP_LISTENER):
    """Class for objects found in TcpE pools"""

    def _ipv4_or_ipv6(self, inaddr):

        if self.get_address_family() == AF_INET:
            return inet_ntop(socket.AF_INET, inaddr.addr4)
        else:
            return inet_ntop(socket.AF_INET6, inaddr.addr6)

    def get_local_address(self):
        try:
            inaddr = self.AddrInfo.dereference().Local.\
                                pData.dereference().dereference()

            return self._ipv4_or_ipv6(inaddr)

        except exceptions.InvalidAddressException:
            return None

    def get_remote_address(self):
        try:
            inaddr = self.AddrInfo.dereference().\
                                Remote.dereference()

            return self._ipv4_or_ipv6(inaddr)

        except exceptions.InvalidAddressException:
            return None

    def is_valid(self):

        if self.State not in TCP_STATE_ENUM:
            vollog.debug("invalid due to invalid tcp state {}".format(self.State))
            return False

        try:
            if self.get_address_family() not in (AF_INET, AF_INET6):
                vollog.debug("invalid due to invalid address_family {}".format(self.get_address_family()))
                return False

            if not self.get_local_address() and (not self.get_owner() or self.get_owner().UniqueProcessId == 0 or self.get_owner().UniqueProcessId > 65535):
                vollog.debug("invalid due to invalid owner data")
                return False

        except exceptions.InvalidAddressException:
            vollog.debug("invalid due to invalid address access")
            return False

        return True

class _UDP_ENDPOINT(_TCP_LISTENER):
    """Class for objects found in UdpA pools"""

class _LOCAL_ADDRESS(objects.StructType):

    @property
    def inaddr(self):
        return self.pData.dereference().dereference()

class _LOCAL_ADDRESS_WIN10_UDP(objects.StructType):

    @property
    def inaddr(self):
        return self.pData.dereference()

win10_x64_class_types = {
    '_TCP_ENDPOINT': _TCP_ENDPOINT,
    '_TCP_LISTENER': _TCP_LISTENER,
    '_UDP_ENDPOINT': _UDP_ENDPOINT,
    '_LOCAL_ADDRESS': _LOCAL_ADDRESS,
    '_LOCAL_ADDRESS_WIN10_UDP': _LOCAL_ADDRESS_WIN10_UDP
}

class_types = {
    '_TCP_ENDPOINT': _TCP_ENDPOINT,
    '_TCP_LISTENER': _TCP_LISTENER,
    '_UDP_ENDPOINT': _UDP_ENDPOINT,
    '_LOCAL_ADDRESS': _LOCAL_ADDRESS
}
