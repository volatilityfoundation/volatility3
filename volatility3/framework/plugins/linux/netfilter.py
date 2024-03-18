# This file is Copyright 2024 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
from dataclasses import dataclass, field
from abc import ABC, abstractmethod
import logging

from typing import Iterator, List, Tuple
from volatility3.framework import (
    class_subclasses,
    constants,
    interfaces,
    renderers,
)
from volatility3.framework.renderers import format_hints
from volatility3.framework.configuration import requirements
from volatility3.framework.symbols import linux
from volatility3.plugins.linux import lsmod

vollog = logging.getLogger(__name__)


@dataclass
class Proto:
    name: str
    hooks: Tuple[str] = field(default_factory=tuple)


PROTO_NOT_IMPLEMENTED = Proto(name="UNSPEC")

NF_INET_HOOKS = ("PRE_ROUTING", "LOCAL_IN", "FORWARD", "LOCAL_OUT", "POST_ROUTING")
NF_DEC_HOOKS = (
    "PRE_ROUTING",
    "LOCAL_IN",
    "FORWARD",
    "LOCAL_OUT",
    "POST_ROUTING",
    "HELLO",
    "ROUTE",
)
NF_ARP_HOOKS = ("IN", "OUT", "FORWARD")
NF_NETDEV_HOOKS = ("INGRESS", "EGRESS")
LARGEST_HOOK_NUMBER = max(
    len(NF_INET_HOOKS), len(NF_DEC_HOOKS), len(NF_ARP_HOOKS), len(NF_NETDEV_HOOKS)
)


class AbstractNetfilter(ABC):
    """Netfilter Abstract Base Classes handling details across various
    Netfilter implementations, including constants, helpers, and common
    routines.
    """

    PROTO_HOOKS = (
        PROTO_NOT_IMPLEMENTED,  # NFPROTO_UNSPEC
        Proto(name="INET", hooks=NF_INET_HOOKS),  # From kernels 3.14
        Proto(name="IPV4", hooks=NF_INET_HOOKS),
        Proto(name="ARP", hooks=NF_ARP_HOOKS),
        PROTO_NOT_IMPLEMENTED,
        Proto(name="NETDEV", hooks=NF_NETDEV_HOOKS),
        PROTO_NOT_IMPLEMENTED,
        Proto(name="BRIDGE", hooks=NF_INET_HOOKS),
        PROTO_NOT_IMPLEMENTED,
        PROTO_NOT_IMPLEMENTED,
        Proto(name="IPV6", hooks=NF_INET_HOOKS),
        PROTO_NOT_IMPLEMENTED,
        Proto(name="DECNET", hooks=NF_DEC_HOOKS),  # Removed in kernel 6.1
    )
    NF_MAX_HOOKS = LARGEST_HOOK_NUMBER + 1

    def __init__(
        self,
        context: interfaces.context.ContextInterface,
        config: interfaces.configuration.HierarchicalDict,
    ):
        self._context = context
        self._config = config
        symbol_table = self._config["kernel"]
        self.vmlinux = context.modules[symbol_table]
        self.layer_name = self.vmlinux.layer_name

        modules = lsmod.Lsmod.list_modules(context, symbol_table)
        self.handlers = linux.LinuxUtilities.generate_kernel_handler_info(
            context, symbol_table, modules
        )

        self._set_data_sizes()

    def _set_data_sizes(self):
        self.ptr_size = self.vmlinux.get_type("pointer").size
        self.list_head_size = self.vmlinux.get_type("list_head").size

    @classmethod
    def run_all(
        cls,
        context: interfaces.context.ContextInterface,
        config: interfaces.configuration.HierarchicalDict,
    ) -> Iterator[Tuple[int, str, str, int, int, str, bool]]:
        """It calls each subclass symtab_checks() to test the required
        conditions to that specific kernel implementation.

        Args:
            context: The volatility3 context on which to operate
            config: Core configuration

        Yields:
            The kmsg records. Same as _run()
        """
        vmlinux = context.modules[config["kernel"]]

        implementation_inst = None  # type: ignore
        for subclass in class_subclasses(cls):
            if not subclass.symtab_checks(vmlinux=vmlinux):
                vollog.log(
                    constants.LOGLEVEL_VVVV,
                    "Netfilter implementation '%s' doesn't match this memory dump",
                    subclass.__name__,
                )
                continue

            vollog.log(
                constants.LOGLEVEL_VVVV,
                "Netfilter implementation '%s' matches!",
                subclass.__name__,
            )
            implementation_inst = subclass(context=context, config=config)
            # More than one class could be executed for an specific kernel version
            # For instance: Netfilter Ingress hooks
            yield from implementation_inst._run()

        if implementation_inst is None:
            vollog.error("Unsupported Netfilter kernel implementation")

    def _run(self) -> Iterator[Tuple[int, str, str, int, int, str, bool]]:
        """Iterates over namespaces and protocols, executing various callbacks that
        allow  customization of the code to the specific data structure used in a
        particular kernel implementation

            get_hooks_container(net, proto_name, hook_name)
                It returns the data structure used in a specific kernel implementation
                to store the hooks for a respective namespace and protocol, basically:
                    For Ingress hooks:
                        network_namespace[] -> net_device[] -> nf_hooks_ingress[]
                    For egress hooks:
                        network_namespace[] -> net_device[] -> nf_hooks_egress[]
                    For all the other Netfilter hooks:
                        <= 4.2.8
                            nf_hooks[]
                        >= 4.3
                            network_namespace[] -> nf.hooks[]

            get_hook_ops(hook_container, proto_idx, hook_idx)
                Give the 'hook_container' got in get_hooks_container(), it
                returns an iterable of 'nf_hook_ops' elements for a respective protocol
                and hook type.

        Returns:
            netns [int]: Network namespace id
            proto_name [str]: Protocol name
            hook_name [str]: Hook name
            priority [int]: Priority
            hook_ops_hook [int]: Hook address
            module_name [str]: Linux kernel module name
            hooked [bool]: hooked?
        """
        for netns, net in self.get_net_namespaces():
            for proto_idx, proto_name, hook_idx, hook_name in self._proto_hook_loop():
                hooks_container = self.get_hooks_container(net, proto_name, hook_name)

                for hook_container in hooks_container:
                    for hook_ops in self.get_hook_ops(
                        hook_container, proto_idx, hook_idx
                    ):
                        if not hook_ops:
                            continue

                        priority = int(hook_ops.priority)
                        hook_ops_hook = hook_ops.hook
                        module_name = self.get_module_name_for_address(hook_ops_hook)
                        hooked = module_name is not None

                        yield netns, proto_name, hook_name, priority, hook_ops_hook, module_name, hooked

    @classmethod
    @abstractmethod
    def symtab_checks(cls, vmlinux: interfaces.context.ModuleInterface) -> bool:
        """This method on each sublasss will be called to evaluate if the kernel
        being analyzed fulfill the type & symbols requirements for the implementation.
        The first class returning True will be instantiated and called via the
        run() method.

        Returns:
            bool: True if the kernel being analyzed fulfill the class requirements.
        """

    def _proto_hook_loop(self) -> Iterator[Tuple[int, str, int, str]]:
        """Flattens the protocol families and hooks"""
        for proto_idx, proto in enumerate(AbstractNetfilter.PROTO_HOOKS):
            if proto == PROTO_NOT_IMPLEMENTED:
                continue
            if proto.name not in self.subscribed_protocols():
                # This protocol is not managed in this object
                continue
            for hook_idx, hook_name in enumerate(proto.hooks):
                yield proto_idx, proto.name, hook_idx, hook_name

    def build_nf_hook_ops_array(self, nf_hook_entries):
        """Function helper to build the nf_hook_ops array when it is not part of the
        struct 'nf_hook_entries' definition.

        nf_hook_ops was stored adjacent in memory to the nf_hook_entry array, in the
        new struct 'nf_hook_entries'. However, this 'nf_hooks_ops' array 'orig_ops' is
        not part of the 'nf_hook_entries' struct. So, we need to calculate the offset.

            struct nf_hook_entries {
                u16                         num_hook_entries; /* plus padding */
                struct nf_hook_entry        hooks[];
                //const struct nf_hook_ops *orig_ops[];
            }
        """
        nf_hook_entry_size = self.vmlinux.get_type("nf_hook_entry").size
        orig_ops_addr = (
            nf_hook_entries.hooks.vol.offset
            + nf_hook_entry_size * nf_hook_entries.num_hook_entries
        )
        orig_ops = self._context.object(
            object_type=self.get_symbol_fullname("array"),
            offset=orig_ops_addr,
            subtype=self.vmlinux.get_type("pointer"),
            layer_name=self.layer_name,
            count=nf_hook_entries.num_hook_entries,
        )

        return orig_ops

    def subscribed_protocols(self) -> Tuple[str]:
        """Allows to select which PROTO_HOOKS protocols will be processed by the
        Netfiler subclass.
        """

        # Most implementation handlers respond to these protocols, except for
        # the ingress hook, which specifically handles the 'NETDEV' protocol.
        # However, there is no corresponding Netfilter hook implementation for
        # the INET protocol in the kernel. AFAIU, this is used as
        # 'NFPROTO_INET = NFPROTO_IPV4 || NFPROTO_IPV6'
        # in other parts of the kernel source code.
        return ("IPV4", "ARP", "BRIDGE", "IPV6", "DECNET")

    def get_module_name_for_address(self, addr) -> str:
        """Helper to obtain the module and symbol name in the format needed for the
        output of this plugin.
        """
        module_name, symbol_name = linux.LinuxUtilities.lookup_module_address(
            self.vmlinux, self.handlers, addr
        )

        if module_name == "UNKNOWN":
            module_name = None

        if symbol_name != "N/A":
            module_name = f"[{symbol_name}]"

        return module_name

    def get_net_namespaces(self):
        """Common function to retrieve the different namespaces.
        From 4.3 on, all the implementations use network namespaces.
        """
        nethead = self.vmlinux.object_from_symbol("net_namespace_list")
        symbol_net_name = self.get_symbol_fullname("net")
        for net in nethead.to_list(symbol_net_name, "list"):
            net_ns_id = net.ns.inum
            yield net_ns_id, net

    def get_hooks_container(self, net, proto_name, hook_name):
        """Returns the data structure used in a specific kernel implementation to store
        the hooks for a respective namespace and protocol.

        Except for kernels < 4.3, all the implementations use network namespaces.
        Also the data structure which contains the hooks, even though it changes its
        implementation and/or data type, it is always in this location.
        """
        yield net.nf.hooks

    def get_hook_ops(self, hook_container, proto_idx, hook_idx):
        """Given the hook_container obtained from get_hooks_container(), it
        returns an iterable of 'nf_hook_ops' elements for a corresponding protocol
        and hook type.

        This is the most variable/unstable part of all Netfilter hook designs, it
        changes almost in every single implementation.
        """
        raise NotImplementedError("You must implement this method")

    def get_symbol_fullname(self, symbol_basename: str) -> str:
        """Given a short symbol or type name, it returns its full name"""
        return self.vmlinux.symbol_table_name + constants.BANG + symbol_basename

    @staticmethod
    def get_member_type(
        vol_type: interfaces.objects.Template, member_name: str
    ) -> List[str]:
        """Returns a list of types/subtypes belonging to the given type member.

        Args:
            vol_type (interfaces.objects.Template): A vol3 type object
            member_name (str): The member name

        Returns:
            list: A list of types/subtypes
        """
        _size, vol_obj = vol_type.vol.members[member_name]
        type_name = vol_obj.type_name
        type_basename = type_name.split(constants.BANG)[1]
        member_type = [type_basename]
        cur_type = vol_obj
        while hasattr(cur_type, "subtype"):
            subtype_name = cur_type.subtype.type_name
            subtype_basename = subtype_name.split(constants.BANG)[1]
            member_type.append(subtype_basename)
            cur_type = cur_type.subtype

        return member_type


class NetfilterImp_to_4_3(AbstractNetfilter):
    """At this point, Netfilter hooks were implemented as a linked list of struct
    'nf_hook_ops' type. One linked list per protocol per hook type.
    It was like that until 4.2.8.

        struct list_head nf_hooks[NFPROTO_NUMPROTO][NF_MAX_HOOKS];
    """

    @classmethod
    def symtab_checks(cls, vmlinux) -> bool:
        return vmlinux.has_symbol("nf_hooks")

    def get_net_namespaces(self):
        # In kernels <= 4.2.8 netfilter hooks are not implemented per namespaces
        netns, net = renderers.NotAvailableValue(), renderers.NotAvailableValue()
        yield netns, net

    def get_hooks_container(self, net, proto_name, hook_name):
        nf_hooks = self.vmlinux.object_from_symbol("nf_hooks")
        if not nf_hooks:
            return

        yield nf_hooks

    def get_hook_ops(self, hook_container, proto_idx, hook_idx):
        list_head = hook_container[proto_idx][hook_idx]
        nf_hooks_ops_name = self.get_symbol_fullname("nf_hook_ops")
        return list_head.to_list(nf_hooks_ops_name, "list")


class NetfilterImp_4_3_to_4_9(AbstractNetfilter):
    """Netfilter hooks were added to network namepaces in 4.3.
    It is still implemented as a linked list of 'struct nf_hook_ops' type but inside a
    network namespace. One linked list per protocol per hook type.

        struct net { ... struct netns_nf nf; ... }
        struct netns_nf { ...
            struct list_head hooks[NFPROTO_NUMPROTO][NF_MAX_HOOKS]; ... }
    """

    @classmethod
    def symtab_checks(cls, vmlinux) -> bool:
        return (
            vmlinux.has_symbol("net_namespace_list")
            and vmlinux.has_type("netns_nf")
            and vmlinux.get_type("netns_nf").has_member("hooks")
            and cls.get_member_type(vmlinux.get_type("netns_nf"), "hooks")
            == ["array", "array", "list_head"]
        )

    def get_hook_ops(self, hook_container, proto_idx, hook_idx):
        list_head = hook_container[proto_idx][hook_idx]
        nf_hooks_ops_name = self.get_symbol_fullname("nf_hook_ops")
        return list_head.to_list(nf_hooks_ops_name, "list")


class NetfilterImp_4_9_to_4_14(AbstractNetfilter):
    """In this range of kernel versions, the doubly-linked lists of netfilter hooks were
    replaced by an array of arrays of 'nf_hook_entry' pointers in a singly-linked lists.
        struct net { ... struct netns_nf nf; ... }
        struct netns_nf { ..
            struct nf_hook_entry __rcu *hooks[NFPROTO_NUMPROTO][NF_MAX_HOOKS]; ... }

    Also in v4.10 the struct nf_hook_entry changed, a hook function pointer was added to
    it. However, for simplicity of this design, we will still take the hook address from
    the 'nf_hook_ops'. As per v5.0-rc2, the hook address is duplicated in both sides.
    - v4.9:
        struct nf_hook_entry {
            struct nf_hook_entry      *next;
            struct nf_hook_ops        ops;
            const struct nf_hook_ops  *orig_ops; };
    - v4.10:
        struct nf_hook_entry {
            struct nf_hook_entry      *next;
            nf_hookfn                 *hook;
            void                      *priv;
            const struct nf_hook_ops  *orig_ops; };
    (*) Even though the hook address is in the struct 'nf_hook_entry', we use the
    original 'nf_hook_ops' hook address value, the one which was filled by the user, to
    make it uniform to all the implementations.
    """

    @classmethod
    def symtab_checks(cls, vmlinux) -> bool:
        hooks_type = ["array", "array", "pointer", "nf_hook_entry"]
        return (
            vmlinux.has_symbol("net_namespace_list")
            and vmlinux.has_type("netns_nf")
            and vmlinux.get_type("netns_nf").has_member("hooks")
            and cls.get_member_type(vmlinux.get_type("netns_nf"), "hooks") == hooks_type
        )

    def _get_hook_ops(self, hook_container, proto_idx, hook_idx):
        list_head = hook_container[proto_idx][hook_idx]
        nf_hooks_ops_name = self.get_symbol_fullname("nf_hook_ops")
        return list_head.to_list(nf_hooks_ops_name, "list")

    def get_hook_ops(self, hook_container, proto_idx, hook_idx):
        nf_hook_entry_list = hook_container[proto_idx][hook_idx]
        while nf_hook_entry_list:
            yield nf_hook_entry_list.orig_ops
            nf_hook_entry_list = nf_hook_entry_list.next


class NetfilterImp_4_14_to_4_16(AbstractNetfilter):
    """'nf_hook_ops' was removed from struct 'nf_hook_entry'. Instead, it was stored
    adjacent in memory to the 'nf_hook_entry' array, in the new struct 'nf_hook_entries'
    However, 'orig_ops' is not part of the 'nf_hook_entries' struct definition. So, we
    have to craft it by hand.

        struct net { ... struct netns_nf nf; ... }
        struct netns_nf {
            struct nf_hook_entries *hooks[NFPROTO_NUMPROTO][NF_MAX_HOOKS]; ... }
        struct nf_hook_entries {
            u16                         num_hook_entries; /* plus padding */
            struct nf_hook_entry        hooks[];
            //const struct nf_hook_ops *orig_ops[]; }
        struct nf_hook_entry {
            nf_hookfn   *hook;
            void        *priv; }

    (*) Even though the hook address is in the struct 'nf_hook_entry', we use the
    original 'nf_hook_ops' hook address value, the one which was filled by the user, to
    make it uniform to all the implementations.
    """

    @classmethod
    def symtab_checks(cls, vmlinux) -> bool:
        hooks_type = ["array", "array", "pointer", "nf_hook_entries"]
        return (
            vmlinux.has_symbol("net_namespace_list")
            and vmlinux.has_type("netns_nf")
            and vmlinux.get_type("netns_nf").has_member("hooks")
            and cls.get_member_type(vmlinux.get_type("netns_nf"), "hooks") == hooks_type
        )

    def get_nf_hook_entries(self, nf_hooks_addr, proto_idx, hook_idx):
        """This allows to support different hook array implementations from this version
        on. For instance, in kernels >= 4.16 this multi-dimensional array is split in
        one-dimensional array of pointers to 'nf_hooks_entries' per each protocol."""
        return nf_hooks_addr[proto_idx][hook_idx]

    def get_hook_ops(self, hook_container, proto_idx, hook_idx):
        nf_hook_entries = self.get_nf_hook_entries(hook_container, proto_idx, hook_idx)
        if not nf_hook_entries:
            return

        nf_hook_ops_name = self.get_symbol_fullname("nf_hook_ops")
        nf_hook_ops_ptr_arr = self.build_nf_hook_ops_array(nf_hook_entries)
        for nf_hook_ops_ptr in nf_hook_ops_ptr_arr:
            nf_hook_ops = nf_hook_ops_ptr.dereference().cast(nf_hook_ops_name)
            yield nf_hook_ops


class NetfilterImp_4_16_to_latest(NetfilterImp_4_14_to_4_16):
    """The multidimensional array of nf_hook_entries was split in a one-dimensional
    array per each protocol.

        struct net {
            struct netns_nf nf; ... }
        struct  netns_nf  {
            struct nf_hook_entries * hooks_ipv4[NF_INET_NUMHOOKS];
            struct nf_hook_entries * hooks_ipv6[NF_INET_NUMHOOKS];
            struct nf_hook_entries * hooks_arp[NF_ARP_NUMHOOKS];
            struct nf_hook_entries * hooks_bridge[NF_INET_NUMHOOKS];
            struct nf_hook_entries * hooks_decnet[NF_DN_NUMHOOKS]; ... }
        struct nf_hook_entries {
                u16 num_hook_entries; /* plus padding */
                struct nf_hook_entry hooks[];
                //const struct nf_hook_ops *orig_ops[]; }
        struct nf_hook_entry {
            nf_hookfn   *hook;
                void *priv; }

    (*) Even though the hook address is in the struct nf_hook_entry, we use the original
    nf_hook_ops hook address value, the one which was filled by the user, to make it
    uniform to all the implementations.
    """

    @classmethod
    def symtab_checks(cls, vmlinux) -> bool:
        return (
            vmlinux.has_symbol("net_namespace_list")
            and vmlinux.has_type("netns_nf")
            and vmlinux.get_type("netns_nf").has_member("hooks_ipv4")
        )

    def get_hooks_container(self, net, proto_name, hook_name):
        try:
            if proto_name == "IPV4":
                net_nf_hooks = net.nf.hooks_ipv4
            elif proto_name == "ARP":
                net_nf_hooks = net.nf.hooks_arp
            elif proto_name == "BRIDGE":
                net_nf_hooks = net.nf.hooks_bridge
            elif proto_name == "IPV6":
                net_nf_hooks = net.nf.hooks_ipv6
            elif proto_name == "DECNET":
                net_nf_hooks = net.nf.hooks_decnet
            else:
                return

            yield net_nf_hooks

        except AttributeError:
            # Protocol family disabled at kernel compilation
            #  CONFIG_NETFILTER_FAMILY_ARP=n ||
            #  CONFIG_NETFILTER_FAMILY_BRIDGE=n ||
            #  CONFIG_DECNET=n
            pass

    def _get_nf_hook_entries_ptr(self, nf_hooks_addr, proto_idx, hook_idx):
        nf_hook_entries_ptr = nf_hooks_addr[hook_idx]
        return nf_hook_entries_ptr

    def get_nf_hook_entries(self, nf_hooks_addr, proto_idx, hook_idx):
        return nf_hooks_addr[hook_idx]


class AbstractNetfilterNetDev(AbstractNetfilter):
    """Base class to handle the Netfilter NetDev hooks.
    It won't be executed. It has some common functions to all Netfilter NetDev hook
    implementions.

    Netfilter NetDev hooks are set per network device which belongs to a network
    namespace.
    """

    @classmethod
    def symtab_checks(cls, vmlinux) -> bool:
        return False

    def subscribed_protocols(self):
        return ("NETDEV",)

    def get_hooks_container(self, net, proto_name, hook_name):
        net_device_type = self.vmlinux.get_type("net_device")
        net_device_name = self.get_symbol_fullname("net_device")
        for net_device in net.dev_base_head.to_list(net_device_name, "dev_list"):
            if hook_name == "INGRESS":
                if net_device_type.has_member("nf_hooks_ingress"):
                    # CONFIG_NETFILTER_INGRESS=y
                    yield net_device.nf_hooks_ingress

            elif hook_name == "EGRESS":
                if net_device_type.has_member("nf_hooks_egress"):
                    # CONFIG_NETFILTER_EGRESS=y
                    yield net_device.nf_hooks_egress


class NetfilterNetDevImp_4_2_to_4_9(AbstractNetfilterNetDev):
    """This is the first version of Netfilter Ingress hooks which was implemented using
    a doubly-linked list of 'nf_hook_ops'.
        struct list_head nf_hooks_ingress;
    """

    @classmethod
    def symtab_checks(cls, vmlinux) -> bool:
        hooks_type = ["list_head"]
        return (
            vmlinux.has_symbol("net_namespace_list")
            and vmlinux.has_type("net_device")
            and vmlinux.get_type("net_device").has_member("nf_hooks_ingress")
            and cls.get_member_type(vmlinux.get_type("net_device"), "nf_hooks_ingress")
            == hooks_type
        )

    def get_hook_ops(self, hook_container, proto_idx, hook_idx):
        nf_hooks_ingress = hook_container
        nf_hook_ops_name = self.get_symbol_fullname("nf_hook_ops")
        return nf_hooks_ingress.to_list(nf_hook_ops_name, "list")


class NetfilterNetDevImp_4_9_to_4_14(AbstractNetfilterNetDev):
    """In 4.9 it was changed to a simple singly-linked list.
    struct nf_hook_entry * nf_hooks_ingress;
    """

    @classmethod
    def symtab_checks(cls, vmlinux) -> bool:
        hooks_type = ["pointer", "nf_hook_entry"]
        return (
            vmlinux.has_symbol("net_namespace_list")
            and vmlinux.has_type("net_device")
            and vmlinux.get_type("net_device").has_member("nf_hooks_ingress")
            and cls.get_member_type(vmlinux.get_type("net_device"), "nf_hooks_ingress")
            == hooks_type
        )

    def get_hook_ops(self, hook_container, proto_idx, hook_idx):
        nf_hooks_ingress_ptr = hook_container
        if not nf_hooks_ingress_ptr:
            return

        while nf_hooks_ingress_ptr:
            nf_hook_entry = nf_hooks_ingress_ptr.dereference()
            orig_ops = nf_hook_entry.orig_ops.dereference()
            yield orig_ops
            nf_hooks_ingress_ptr = nf_hooks_ingress_ptr.next


class NetfilterNetDevImp_4_14_to_latest(AbstractNetfilterNetDev):
    """In 4.14 the hook list was converted to an array of pointers inside the struct
    'nf_hook_entries':
    struct nf_hook_entries * nf_hooks_ingress;
    struct nf_hook_entries {
            u16 num_hook_entries;
            struct nf_hook_entry        hooks[];
            //const struct nf_hook_ops *orig_ops[]; }
    """

    @classmethod
    def symtab_checks(cls, vmlinux) -> bool:
        hooks_type = ["pointer", "nf_hook_entries"]
        return (
            vmlinux.has_symbol("net_namespace_list")
            and vmlinux.has_type("net_device")
            and vmlinux.get_type("net_device").has_member("nf_hooks_ingress")
            and cls.get_member_type(vmlinux.get_type("net_device"), "nf_hooks_ingress")
            == hooks_type
        )

    def get_hook_ops(self, hook_container, proto_idx, hook_idx):
        nf_hook_entries = hook_container
        if not nf_hook_entries:
            return

        nf_hook_ops_name = self.get_symbol_fullname("nf_hook_ops")
        nf_hook_ops_ptr_arr = self.build_nf_hook_ops_array(nf_hook_entries)
        for nf_hook_ops_ptr in nf_hook_ops_ptr_arr:
            nf_hook_ops = nf_hook_ops_ptr.dereference().cast(nf_hook_ops_name)
            yield nf_hook_ops


class Netfilter(interfaces.plugins.PluginInterface):
    """Lists Netfilter hooks."""

    _required_framework_version = (2, 0, 0)

    _version = (1, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Linux kernel",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.PluginRequirement(
                name="lsmod", plugin=lsmod.Lsmod, version=(2, 0, 0)
            ),
        ]

    def _format_fields(self, fields):
        (
            netns,
            proto_name,
            hook_name,
            priority,
            hook_func,
            module_name,
            hooked,
        ) = fields
        return (
            netns,
            proto_name,
            hook_name,
            priority,
            format_hints.Hex(hook_func),
            module_name,
            str(hooked),
        )

    def _generator(self):
        for fields in AbstractNetfilter.run_all(
            context=self.context, config=self.config
        ):
            yield (0, self._format_fields(fields))

    def run(self):
        headers = [
            ("Net NS", int),
            ("Proto", str),
            ("Hook", str),
            ("Priority", int),
            ("Handler", format_hints.Hex),
            ("Module", str),
            ("Is Hooked", str),
        ]
        return renderers.TreeGrid(headers, self._generator())
