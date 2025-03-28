# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
"""Volatility 3 Linux Constants.

Linux-specific values that aren't found in debug symbols
"""
import enum
from dataclasses import dataclass

KERNEL_NAME = "__kernel__"

"""The value hard coded from the Linux Kernel (hence not extracted from the layer itself)"""

# include/linux/sched.h
PF_KTHREAD = 0x00200000  # I'm a kernel thread

# Standard well-defined IP protocols.
# ref: include/uapi/linux/in.h
IP_PROTOCOLS = {
    0: "IP",
    1: "ICMP",
    2: "IGMP",
    4: "IPIP",
    6: "TCP",
    8: "EGP",
    12: "PUP",
    17: "UDP",
    22: "IDP",
    29: "TP",
    33: "DCCP",
    41: "IPV6",
    46: "RSVP",
    47: "GRE",
    50: "ESP",
    51: "AH",
    92: "MTP",
    94: "BEETPH",
    98: "ENCAP",
    103: "PIM",
    108: "COMP",
    132: "SCTP",
    136: "UDPLITE",
    137: "MPLS",
    143: "ETHERNET",
    255: "RAW",
    262: "MPTCP",
}

# IPV6 extension headers
# ref: include/uapi/linux/in6.h
IPV6_PROTOCOLS = {
    0: "HOPBYHOP_OPTS",
    43: "ROUTING",
    44: "FRAGMENT",
    58: "ICMPv6",
    59: "NO_NEXT",
    60: "DESTINATION_OPTS",
    135: "MOBILITY",
}

# ref: include/net/tcp_states.h
TCP_STATES = (
    "",
    "ESTABLISHED",
    "SYN_SENT",
    "SYN_RECV",
    "FIN_WAIT1",
    "FIN_WAIT2",
    "TIME_WAIT",
    "CLOSE",
    "CLOSE_WAIT",
    "LAST_ACK",
    "LISTEN",
    "CLOSING",
    "TCP_NEW_SYN_RECV",
)

# ref: include/linux/net.h (socket_type enum)
SOCK_TYPES = {
    1: "STREAM",
    2: "DGRAM",
    3: "RAW",
    4: "RDM",
    5: "SEQPACKET",
    6: "DCCP",
    10: "PACKET",
}

# Address families
# ref: include/linux/socket.h
SOCK_FAMILY = (
    "AF_UNSPEC",
    "AF_UNIX",
    "AF_INET",
    "AF_AX25",
    "AF_IPX",
    "AF_APPLETALK",
    "AF_NETROM",
    "AF_BRIDGE",
    "AF_ATMPVC",
    "AF_X25",
    "AF_INET6",
    "AF_ROSE",
    "AF_DECnet",
    "AF_NETBEUI",
    "AF_SECURITY",
    "AF_KEY",
    "AF_NETLINK",
    "AF_PACKET",
    "AF_ASH",
    "AF_ECONET",
    "AF_ATMSVC",
    "AF_RDS",
    "AF_SNA",
    "AF_IRDA",
    "AF_PPPOX",
    "AF_WANPIPE",
    "AF_LLC",
    "AF_IB",
    "AF_MPLS",
    "AF_CAN",
    "AF_TIPC",
    "AF_BLUETOOTH",
    "AF_IUCV",
    "AF_RXRPC",
    "AF_ISDN",
    "AF_PHONET",
    "AF_IEEE802154",
    "AF_CAIF",
    "AF_ALG",
    "AF_NFC",
    "AF_VSOCK",
    "AF_KCM",
    "AF_QIPCRTR",
    "AF_SMC",
    "AF_XDP",
)

# Socket states
# ref: include/uapi/linux/net.h
SOCKET_STATES = ("FREE", "UNCONNECTED", "CONNECTING", "CONNECTED", "DISCONNECTING")

# Netlink protocols
# ref: include/uapi/linux/netlink.h
NETLINK_PROTOCOLS = (
    "NETLINK_ROUTE",
    "NETLINK_UNUSED",
    "NETLINK_USERSOCK",
    "NETLINK_FIREWALL",
    "NETLINK_SOCK_DIAG",
    "NETLINK_NFLOG",
    "NETLINK_XFRM",
    "NETLINK_SELINUX",
    "NETLINK_ISCSI",
    "NETLINK_AUDIT",
    "NETLINK_FIB_LOOKUP",
    "NETLINK_CONNECTOR",
    "NETLINK_NETFILTER",
    "NETLINK_IP6_FW",
    "NETLINK_DNRTMSG",
    "NETLINK_KOBJECT_UEVENT",
    "NETLINK_GENERIC",
    "NETLINK_DM",
    "NETLINK_SCSITRANSPORT",
    "NETLINK_ECRYPTFS",
    "NETLINK_RDMA",
    "NETLINK_CRYPTO",
    "NETLINK_SMC",
)

# Short list of Ethernet Protocol ID's.
# ref: include/uapi/linux/if_ether.h
# Used in AF_PACKET socket family
ETH_PROTOCOLS = {
    0x0001: "ETH_P_802_3",
    0x0002: "ETH_P_AX25",
    0x0003: "ETH_P_ALL",
    0x0004: "ETH_P_802_2",
    0x0005: "ETH_P_SNAP",
    0x0006: "ETH_P_DDCMP",
    0x0007: "ETH_P_WAN_PPP",
    0x0008: "ETH_P_PPP_MP",
    0x0009: "ETH_P_LOCALTALK",
    0x000C: "ETH_P_CAN",
    0x000F: "ETH_P_CANFD",
    0x0010: "ETH_P_PPPTALK",
    0x0011: "ETH_P_TR_802_2",
    0x0016: "ETH_P_CONTROL",
    0x0017: "ETH_P_IRDA",
    0x0018: "ETH_P_ECONET",
    0x0019: "ETH_P_HDLC",
    0x001A: "ETH_P_ARCNET",
    0x001B: "ETH_P_DSA",
    0x001C: "ETH_P_TRAILER",
    0x0060: "ETH_P_LOOP",
    0x00F6: "ETH_P_IEEE802154",
    0x00F7: "ETH_P_CAIF",
    0x00F8: "ETH_P_XDSA",
    0x00F9: "ETH_P_MAP",
    0x0800: "ETH_P_IP",
    0x0805: "ETH_P_X25",
    0x0806: "ETH_P_ARP",
    0x8035: "ETH_P_RARP",
    0x809B: "ETH_P_ATALK",
    0x80F3: "ETH_P_AARP",
    0x8100: "ETH_P_8021Q",
}

# Connection and socket states
# ref: include/net/bluetooth/bluetooth.h
BLUETOOTH_STATES = (
    "",
    "CONNECTED",
    "OPEN",
    "BOUND",
    "LISTEN",
    "CONNECT",
    "CONNECT2",
    "CONFIG",
    "DISCONN",
    "CLOSED",
)

# Bluetooth protocols
# ref: include/net/bluetooth/bluetooth.h
BLUETOOTH_PROTOCOLS = (
    "L2CAP",
    "HCI",
    "SCO",
    "RFCOMM",
    "BNEP",
    "CMTP",
    "HIDP",
    "AVDTP",
)

# Ref: include/uapi/linux/capability.h
CAPABILITIES = (
    "chown",
    "dac_override",
    "dac_read_search",
    "fowner",
    "fsetid",
    "kill",
    "setgid",
    "setuid",
    "setpcap",
    "linux_immutable",
    "net_bind_service",
    "net_broadcast",
    "net_admin",
    "net_raw",
    "ipc_lock",
    "ipc_owner",
    "sys_module",
    "sys_rawio",
    "sys_chroot",
    "sys_ptrace",
    "sys_pacct",
    "sys_admin",
    "sys_boot",
    "sys_nice",
    "sys_resource",
    "sys_time",
    "sys_tty_config",
    "mknod",
    "lease",
    "audit_write",
    "audit_control",
    "setfcap",
    "mac_override",
    "mac_admin",
    "syslog",
    "wake_alarm",
    "block_suspend",
    "audit_read",
    "perfmon",
    "bpf",
    "checkpoint_restore",
)

ELF_MAX_EXTRACTION_SIZE = 1024 * 1024 * 1024 * 4 - 1

# For IFA_* below - Ref: include/net/ipv6.h
IPV6_ADDR_LOOPBACK = 0x0010
IPV6_ADDR_LINKLOCAL = 0x0020
IPV6_ADDR_SITELOCAL = 0x0040
# For inet6_ifaddr - Ref: include/net/if_inet6.h
IFA_HOST = IPV6_ADDR_LOOPBACK
IFA_LINK = IPV6_ADDR_LINKLOCAL
IFA_SITE = IPV6_ADDR_SITELOCAL

# Only for kernels < 3.15 when the net_device_flags enum didn't exist
# ref include/uapi/linux/if.h
NET_DEVICE_FLAGS = {
    "IFF_UP": 0x1,
    "IFF_BROADCAST": 0x2,
    "IFF_DEBUG": 0x4,
    "IFF_LOOPBACK": 0x8,
    "IFF_POINTOPOINT": 0x10,
    "IFF_NOTRAILERS": 0x20,
    "IFF_RUNNING": 0x40,
    "IFF_NOARP": 0x80,
    "IFF_PROMISC": 0x100,
    "IFF_ALLMULTI": 0x200,
    "IFF_MASTER": 0x400,
    "IFF_SLAVE": 0x800,
    "IFF_MULTICAST": 0x1000,
    "IFF_PORTSEL": 0x2000,
    "IFF_AUTOMEDIA": 0x4000,
    "IFF_DYNAMIC": 0x8000,
    "IFF_LOWER_UP": 0x10000,
    "IFF_DORMANT": 0x20000,
    "IFF_ECHO": 0x40000,
}


# Kernels >= 2.6.17. See IF_OPER_* in include/uapi/linux/if.h
class IF_OPER_STATES(enum.Enum):
    """RFC 2863 - Network interface operational status"""

    UNKNOWN = 0
    NOTPRESENT = 1
    DOWN = 2
    LOWERLAYERDOWN = 3
    TESTING = 4
    DORMANT = 5
    UP = 6


class ELF_IDENT(enum.IntEnum):
    """ELF header e_ident indexes"""

    EI_MAG0 = 0
    EI_MAG1 = 1
    EI_MAG2 = 2
    EI_MAG3 = 3
    EI_CLASS = 4
    EI_DATA = 5
    EI_VERSION = 6
    EI_OSABI = 7
    EI_PAD = 8


class ELF_CLASS(enum.IntEnum):
    """ELF header class types"""

    ELFCLASSNONE = 0
    ELFCLASS32 = 1
    ELFCLASS64 = 2


# PTrace
PT_OPT_FLAG_SHIFT = 3

PTRACE_EVENT_FORK = 1
PTRACE_EVENT_VFORK = 2
PTRACE_EVENT_CLONE = 3
PTRACE_EVENT_EXEC = 4
PTRACE_EVENT_VFORK_DONE = 5
PTRACE_EVENT_EXIT = 6
PTRACE_EVENT_SECCOMP = 7

PTRACE_O_EXITKILL = 1 << 20
PTRACE_O_SUSPEND_SECCOMP = 1 << 21


class PT_FLAGS(enum.Flag):
    "PTrace flags"

    PT_PTRACED = 0x00001
    PT_SEIZED = 0x10000

    PT_TRACESYSGOOD = 1 << (PT_OPT_FLAG_SHIFT + 0)
    PT_TRACE_FORK = 1 << (PT_OPT_FLAG_SHIFT + PTRACE_EVENT_FORK)
    PT_TRACE_VFORK = 1 << (PT_OPT_FLAG_SHIFT + PTRACE_EVENT_VFORK)
    PT_TRACE_CLONE = 1 << (PT_OPT_FLAG_SHIFT + PTRACE_EVENT_CLONE)
    PT_TRACE_EXEC = 1 << (PT_OPT_FLAG_SHIFT + PTRACE_EVENT_EXEC)
    PT_TRACE_VFORK_DONE = 1 << (PT_OPT_FLAG_SHIFT + PTRACE_EVENT_VFORK_DONE)
    PT_TRACE_EXIT = 1 << (PT_OPT_FLAG_SHIFT + PTRACE_EVENT_EXIT)
    PT_TRACE_SECCOMP = 1 << (PT_OPT_FLAG_SHIFT + PTRACE_EVENT_SECCOMP)

    PT_EXITKILL = PTRACE_O_EXITKILL << PT_OPT_FLAG_SHIFT
    PT_SUSPEND_SECCOMP = PTRACE_O_SUSPEND_SECCOMP << PT_OPT_FLAG_SHIFT

    @property
    def flags(self) -> str:
        """Returns the ptrace flags string"""
        return str(self).replace(self.__class__.__name__ + ".", "")


# Boot time
NSEC_PER_SEC = 1e9


# Valid sizes for modules. Note that the Linux kernel does not define these values; they
# are based on empirical observations of typical memory allocations for kernel modules.
# We use this to verify that the found module falls within reasonable limits.
MODULE_MAXIMUM_CORE_SIZE = 20000000
MODULE_MAXIMUM_CORE_TEXT_SIZE = 20000000
MODULE_MINIMUM_SIZE = 4096

# Kallsyms
KSYM_NAME_LEN = 512
NM_TYPES_DESC = {
    "a": "Symbol is absolute and doesn't change during linking",
    "b": "Symbol in the BSS section, typically holding zero-initialized or uninitialized data",
    "c": "Symbol is common, typically holding uninitialized data",
    "d": "Symbol is in the initialized data section",
    "g": "Symbol is in an initialized data section for small objects",
    "i": "Symbol is an indirect reference to another symbol",
    "N": "Symbol is a debugging symbol",
    "n": "Symbol is in a non-data, non-code, non-debug read-only section",
    "p": "Symbol is in a stack unwind section",
    "r": "Symbol is in a read only data section",
    "s": "Symbol is in an uninitialized or zero-initialized data section for small objects",
    "t": "Symbol is in the text (code) section",
    "U": "Symbol is undefined",
    "u": "Symbol is a unique global symbol",
    "V": "Symbol is a weak object, with a default value",
    "v": "Symbol is a weak object",
    "W": "Symbol is a weak symbol but not marked as a weak object symbol, with a default value",
    "w": "Symbol is a weak symbol but not marked as a weak object symbol",
    "?": "Symbol type is unknown",
}

# VMCOREINFO
VMCOREINFO_MAGIC = b"VMCOREINFO\x00"
# Aligned to 4 bytes. See storenote() in kernels < 4.19 or append_kcore_note() in kernels >= 4.19
VMCOREINFO_MAGIC_ALIGNED = VMCOREINFO_MAGIC + b"\x00"
OSRELEASE_TAG = b"OSRELEASE="


@dataclass
class TaintFlag:
    shift: int
    desc: str
    when_present: bool
    module: bool


TAINT_FLAGS = {
    "P": TaintFlag(
        shift=1 << 0, desc="PROPRIETARY_MODULE", when_present=True, module=True
    ),
    "G": TaintFlag(
        shift=1 << 0, desc="PROPRIETARY_MODULE", when_present=False, module=True
    ),
    "F": TaintFlag(shift=1 << 1, desc="FORCED_MODULE", when_present=True, module=False),
    "S": TaintFlag(
        shift=1 << 2, desc="CPU_OUT_OF_SPEC", when_present=True, module=False
    ),
    "R": TaintFlag(shift=1 << 3, desc="FORCED_RMMOD", when_present=True, module=False),
    "M": TaintFlag(shift=1 << 4, desc="MACHINE_CHECK", when_present=True, module=False),
    "B": TaintFlag(shift=1 << 5, desc="BAD_PAGE", when_present=True, module=False),
    "U": TaintFlag(shift=1 << 6, desc="USER", when_present=True, module=False),
    "D": TaintFlag(shift=1 << 7, desc="DIE", when_present=True, module=False),
    "A": TaintFlag(
        shift=1 << 8, desc="OVERRIDDEN_ACPI_TABLE", when_present=True, module=False
    ),
    "W": TaintFlag(shift=1 << 9, desc="WARN", when_present=True, module=False),
    "C": TaintFlag(shift=1 << 10, desc="CRAP", when_present=True, module=True),
    "I": TaintFlag(
        shift=1 << 11, desc="FIRMWARE_WORKAROUND", when_present=True, module=False
    ),
    "O": TaintFlag(shift=1 << 12, desc="OOT_MODULE", when_present=True, module=True),
    "E": TaintFlag(
        shift=1 << 13, desc="UNSIGNED_MODULE", when_present=True, module=True
    ),
    "L": TaintFlag(shift=1 << 14, desc="SOFTLOCKUP", when_present=True, module=False),
    "K": TaintFlag(shift=1 << 15, desc="LIVEPATCH", when_present=True, module=True),
    "X": TaintFlag(shift=1 << 16, desc="AUX", when_present=True, module=True),
    "T": TaintFlag(shift=1 << 17, desc="RANDSTRUCT", when_present=True, module=True),
    "N": TaintFlag(shift=1 << 18, desc="TEST", when_present=True, module=True),
}
"""Flags used to taint kernel and modules, for debugging purposes.

Map based on 6.12-rc5.

Documentation :
    - https://www.kernel.org/doc/Documentation/admin-guide/sysctl/kernel.rst#:~:text=guide/sysrq.rst.-,tainted,-%3D%3D%3D%3D%3D%3D%3D%0A%0ANon%2Dzero%20if
    - https://www.kernel.org/doc/Documentation/admin-guide/tainted-kernels.rst#:~:text=More%20detailed%20explanation%20for%20tainting
    - taint_flag kernel struct
    - taint_flags kernel constant
"""

## ELF related constants

# Elf Symbol Bindings
STB_LOCAL = 0
STB_GLOBAL = 1

# Elf Symbol Types
STT_NOTYPE = 0
STT_OBJECT = 1
STT_FUNC = 2
STT_SECTION = 3

# Elf Section Types
SHT_NULL = 0
SHT_PROGBITS = 1
SHT_SYMTAB = 2
SHT_STRTAB = 3
SHT_RELA = 4
SHT_NOTE = 7

# Elf Section Attributes
SHF_WRITE = 1
SHF_ALLOC = 2
SHF_EXECINSTR = 4
