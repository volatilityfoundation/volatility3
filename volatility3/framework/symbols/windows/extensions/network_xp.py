# This file is Copyright 2026 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

import logging
import socket
from typing import Optional

from volatility3.framework import interfaces, objects, renderers
from volatility3.framework.renderers import conversion

vollog = logging.getLogger(__name__)

# IPPROTO values stored in _ADDRESS_OBJECT.Protocol
PROTO_NAMES = {6: "TCP", 17: "UDP"}


def _ip4(addr) -> str:
    """Render a raw 4-byte IPv4 address (network order) as dotted-quad."""
    return socket.inet_ntop(socket.AF_INET, bytes(addr))


class _TCPT_OBJECT(objects.StructType):
    """A TCP connection object (pool tag ``TCPT``) used by tcpip.sys on
    Windows XP / Server 2003 (x86)."""

    def get_local_address(self) -> Optional[str]:
        try:
            return _ip4(self.LocalIpAddress)
        except (ValueError, OSError):
            return None

    def get_remote_address(self) -> Optional[str]:
        try:
            return _ip4(self.RemoteIpAddress)
        except (ValueError, OSError):
            return None

    def get_owner_pid(self):
        return self.Pid

    def is_valid(self) -> bool:
        # Reject obvious false positives: PIDs are small, multiples of 4 on
        # XP, and a real connection has at least one non-zero endpoint.
        try:
            pid = int(self.Pid)
            if pid <= 0 or pid > 0xFFFF or pid % 4 != 0:
                return False
            if int(self.LocalPort) == 0 and int(self.RemotePort) == 0:
                return False
            local = self.get_local_address()
            remote = self.get_remote_address()
            if local is None or remote is None:
                return False
            if local == "0.0.0.0" and remote == "0.0.0.0":
                return False
        except Exception:
            return False
        return True


class _ADDRESS_OBJECT(objects.StructType):
    """A bound/listening socket object (pool tag ``TCPA``) used by tcpip.sys
    on Windows XP / Server 2003 (x86)."""

    def get_local_address(self) -> Optional[str]:
        try:
            return _ip4(self.LocalIpAddress)
        except (ValueError, OSError):
            return None

    def get_protocol(self) -> str:
        return PROTO_NAMES.get(int(self.Protocol), str(int(self.Protocol)))

    def get_owner_pid(self):
        return self.Pid

    def get_create_time(self):
        try:
            if int(self.CreateTime) == 0:
                return renderers.NotApplicableValue()
            return conversion.wintime_to_datetime(self.CreateTime)
        except Exception:
            return renderers.UnreadableValue()

    def is_valid(self) -> bool:
        try:
            pid = int(self.Pid)
            # A real socket is owned by a process (never the Idle PID 0) and
            # XP PIDs are small multiples of 4.
            if pid <= 0 or pid > 0xFFFF or pid % 4 != 0:
                return False
            # Only TCP/UDP are tracked via _ADDRESS_OBJECT; anything else is a
            # false positive from tag collision.
            if int(self.Protocol) not in PROTO_NAMES:
                return False
            if int(self.LocalPort) == 0:
                return False
            if self.get_local_address() is None:
                return False
        except Exception:
            return False
        return True


class_types = {
    "_TCPT_OBJECT": _TCPT_OBJECT,
    "_ADDRESS_OBJECT": _ADDRESS_OBJECT,
}
