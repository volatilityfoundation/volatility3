# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
"""Volatility 3 Linux Constants.

Linux-specific values that aren't found in debug symbols
"""
from enum import IntEnum

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


class ELF_IDENT(IntEnum):
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


class ELF_CLASS(IntEnum):
    """ELF header class types"""

    ELFCLASSNONE = 0
    ELFCLASS32 = 1
    ELFCLASS64 = 2
