# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

import logging
import socket
from typing import Dict, Tuple, List, Union

from volatility3.framework import exceptions
from volatility3.framework import objects, interfaces
from volatility3.framework.objects import Array
from volatility3.framework.renderers import conversion

vollog = logging.getLogger(__name__)


def inet_ntop(address_family: int, packed_ip: Union[List[int], Array]) -> str:
    if address_family in [socket.AF_INET6, socket.AF_INET]:
        try:
            return socket.inet_ntop(address_family, bytes(packed_ip))
        except AttributeError:
            raise RuntimeError(
                "This version of python does not have socket.inet_ntop, please upgrade"
            )
    raise socket.error("[Errno 97] Address family not supported by protocol")


# Python's socket.AF_INET6 is 0x1e but Microsoft defines it
# as a constant value of 0x17 in their source code. Thus we
# need Microsoft's since that's what is found in memory.
AF_INET = 2
AF_INET6 = 0x17

# String representations of INADDR_ANY and INADDR6_ANY
inaddr_any = inet_ntop(socket.AF_INET, [0] * 4)
inaddr6_any = inet_ntop(socket.AF_INET6, [0] * 16)


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

    MIN_CREATETIME_YEAR = 1950
    MAX_CREATETIME_YEAR = 2200

    def __init__(
        self,
        context: interfaces.context.ContextInterface,
        type_name: str,
        object_info: interfaces.objects.ObjectInformation,
        size: int,
        members: Dict[str, Tuple[int, interfaces.objects.Template]],
    ) -> None:
        super().__init__(
            context=context,
            type_name=type_name,
            object_info=object_info,
            size=size,
            members=members,
        )

    def get_address_family(self):
        try:
            return self.InetAF.dereference().AddressFamily

        except exceptions.InvalidAddressException:
            return None

    def get_owner(self):
        try:
            return self.member("Owner").dereference()

        except exceptions.InvalidAddressException:
            return None

    def get_owner_pid(self):
        if self.get_owner().is_valid():
            if self.get_owner().has_valid_member("UniqueProcessId"):
                return self.get_owner().UniqueProcessId

        return None

    def get_owner_procname(self):
        if self.get_owner().is_valid():
            if self.get_owner().has_valid_member("ImageFileName"):
                return self.get_owner().ImageFileName.cast(
                    "string",
                    max_length=self.get_owner().ImageFileName.vol.count,
                    errors="replace",
                )

        return None

    def get_create_time(self):
        dt_obj = conversion.wintime_to_datetime(self.CreateTime.QuadPart)

        if isinstance(dt_obj, interfaces.renderers.BaseAbsentValue):
            return dt_obj

        # return None if the timestamp seems invalid
        if not (self.MIN_CREATETIME_YEAR < dt_obj.year < self.MAX_CREATETIME_YEAR):
            return None
        else:
            return dt_obj

    def get_in_addr(self):
        try:
            local_addr = self.LocalAddr.dereference()
            # there is a rare edge case here we have to consider:
            # if the struct has a null pointer at the LocalAddr offset,
            # this generally means this struct has no associated local address.
            # however, sometimes a pointer to the offset of 0 can be valid because
            # it points to a valid virtual memory address of 0. this confuses this
            # plugin because trying to access the nullpointer does not raise any
            # errors, leading to errors later down the line when accessing the
            # pointed-to _IN_ADDR addr4/6 attributes.

            # addr4/6 are at the same offset, accessing the first byte covers both.
            # if this causes no error, we can expect a valid network addr.
            _ = local_addr.pData.dereference().addr4[0]

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
                vollog.debug(
                    "netw obj 0x{:x} invalid due to invalid address_family {}".format(
                        self.vol.offset, self.get_address_family()
                    )
                )
                return False

        except exceptions.InvalidAddressException:
            vollog.debug(
                f"netw obj 0x{self.vol.offset:x} invalid due to invalid address access"
            )
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
            inaddr = self.AddrInfo.dereference().Local.pData.dereference().dereference()

            return self._ipv4_or_ipv6(inaddr)

        except exceptions.InvalidAddressException:
            return None

    def get_remote_address(self):
        try:
            inaddr = self.AddrInfo.dereference().Remote.dereference()

            return self._ipv4_or_ipv6(inaddr)

        except exceptions.InvalidAddressException:
            return None

    def is_valid(self):
        if self.State not in self.State.choices.values():
            vollog.debug(
                f"{type(self)} 0x{self.vol.offset:x} invalid due to invalid tcp state {self.State}"
            )
            return False

        try:
            if self.get_address_family() not in (AF_INET, AF_INET6):
                vollog.debug(
                    f"{type(self)} 0x{self.vol.offset:x} invalid due to invalid address_family {self.get_address_family()}"
                )
                return False

            if not self.get_local_address() and (
                not self.get_owner()
                or self.get_owner().UniqueProcessId == 0
                or self.get_owner().UniqueProcessId > 65535
            ):
                vollog.debug(
                    f"{type(self)} 0x{self.vol.offset:x} invalid due to invalid owner data"
                )
                return False

        except exceptions.InvalidAddressException:
            vollog.debug(
                f"{type(self)} 0x{self.vol.offset:x} invalid due to invalid address access"
            )
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
    "_TCP_ENDPOINT": _TCP_ENDPOINT,
    "_TCP_LISTENER": _TCP_LISTENER,
    "_UDP_ENDPOINT": _UDP_ENDPOINT,
    "_LOCAL_ADDRESS": _LOCAL_ADDRESS,
    "_LOCAL_ADDRESS_WIN10_UDP": _LOCAL_ADDRESS_WIN10_UDP,
}

class_types = {
    "_TCP_ENDPOINT": _TCP_ENDPOINT,
    "_TCP_LISTENER": _TCP_LISTENER,
    "_UDP_ENDPOINT": _UDP_ENDPOINT,
    "_LOCAL_ADDRESS": _LOCAL_ADDRESS,
}
