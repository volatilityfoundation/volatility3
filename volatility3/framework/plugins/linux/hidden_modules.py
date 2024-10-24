# This file is Copyright 2024 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
import logging
from typing import List, Set, Tuple, Iterable
from volatility3.framework import renderers, interfaces, exceptions, objects
from volatility3.framework.constants.architectures import LINUX_ARCHS
from volatility3.framework.renderers import format_hints
from volatility3.framework.configuration import requirements
from volatility3.plugins.linux import lsmod

vollog = logging.getLogger(__name__)


class Hidden_modules(interfaces.plugins.PluginInterface):
    """Carves memory to find hidden kernel modules"""

    _required_framework_version = (2, 10, 0)

    _version = (1, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Linux kernel",
                architectures=LINUX_ARCHS,
            ),
            requirements.PluginRequirement(
                name="lsmod", plugin=lsmod.Lsmod, version=(2, 0, 0)
            ),
        ]

    @staticmethod
    def get_modules_memory_boundaries(
        context: interfaces.context.ContextInterface,
        vmlinux_module_name: str,
    ) -> Tuple[int]:
        """Determine the boundaries of the module allocation area

        Args:
            context: The context to retrieve required elements (layers, symbol tables) from
            vmlinux_module_name: The name of the kernel module on which to operate

        Returns:
            A tuple containing the minimum and maximum addresses for the module allocation area.
        """
        vmlinux = context.modules[vmlinux_module_name]
        if vmlinux.has_symbol("mod_tree"):
            mod_tree = vmlinux.object_from_symbol("mod_tree")
            modules_addr_min = mod_tree.addr_min
            modules_addr_max = mod_tree.addr_max
        elif vmlinux.has_symbol("module_addr_min"):
            modules_addr_min = vmlinux.object_from_symbol("module_addr_min")
            modules_addr_max = vmlinux.object_from_symbol("module_addr_max")

            if isinstance(modules_addr_min, objects.Void):
                # Crap ISF! Here's my best-effort workaround
                vollog.warning(
                    "Your ISF symbols are missing type information. You may need to update "
                    "the ISF using the latest version of dwarf2json"
                )
                # See issue #1041. In the Linux kernel these are "unsigned long"
                for type_name in ("long unsigned int", "unsigned long"):
                    if vmlinux.has_type(type_name):
                        modules_addr_min = modules_addr_min.cast(type_name)
                        modules_addr_max = modules_addr_max.cast(type_name)
                        break
                else:
                    raise exceptions.VolatilityException(
                        "Bad ISF! Please update the ISF using the latest version of dwarf2json"
                    )
        else:
            raise exceptions.VolatilityException(
                "Cannot find the module memory allocation area. Unsupported kernel"
            )

        return modules_addr_min, modules_addr_max

    @classmethod
    def _get_module_address_alignment(
        cls,
        context: interfaces.context.ContextInterface,
        vmlinux_module_name: str,
    ) -> int:
        """Obtain the module memory address alignment.

        struct module is aligned to the L1 cache line, which is typically 64 bytes for most
        common i386/AMD64/ARM64 configurations. In some cases, it can be 128 bytes, but this
        will still work.

        Args:
            context: The context to retrieve required elements (layers, symbol tables) from
            vmlinux_module_name: The name of the kernel module on which to operate

        Returns:
            The struct module alignment
        """
        # FIXME: When dwarf2json/ISF supports type alignments. Read it directly from the type metadata
        # Additionally, while 'context' and 'vmlinux_module_name' are currently unused, they will be
        # essential for retrieving type metadata in the future.
        return 64

    @staticmethod
    def _validate_alignment_patterns(
        addresses: Iterable[int],
        address_alignment: int,
    ) -> bool:
        """Check if the memory addresses meet our alignments patterns

        Args:
            addresses: Iterable with the address values
            address_alignment: Number of bytes for alignment validation

        Returns:
            True if all the addresses meet the alignment
        """
        return all(addr % address_alignment == 0 for addr in addresses)

    @classmethod
    def get_hidden_modules(
        cls,
        context: interfaces.context.ContextInterface,
        vmlinux_module_name: str,
        known_module_addresses: Set[int],
        modules_memory_boundaries: Tuple,
    ) -> Iterable[interfaces.objects.ObjectInterface]:
        """Enumerate hidden modules by taking advantage of memory address alignment patterns

        This technique is much faster and uses less memory than the traditional scan method
        in Volatility2, but it doesn't work with older kernels.

        From kernels 4.2 struct module allocation are aligned to the L1 cache line size.
        In i386/amd64/arm64 this is typically 64 bytes. However, this can be changed in
        the Linux kernel configuration via CONFIG_X86_L1_CACHE_SHIFT. The alignment can
        also be obtained from the DWARF info i.e. DW_AT_alignment<64>, but dwarf2json
        doesn't support this feature yet.
        In kernels < 4.2, alignment attributes are absent in the struct module, meaning
        alignment cannot be guaranteed. Therefore, for older kernels, it's better to use
        the traditional scan technique.

        Args:
            context: The context to retrieve required elements (layers, symbol tables) from
            vmlinux_module_name: The name of the kernel module on which to operate
            known_module_addresses: Set with known module addresses
            modules_memory_boundaries: Minimum and maximum address boundaries for module allocation.
        Yields:
            module objects
        """
        vmlinux = context.modules[vmlinux_module_name]
        vmlinux_layer = context.layers[vmlinux.layer_name]

        module_addr_min, module_addr_max = modules_memory_boundaries
        module_address_alignment = cls._get_module_address_alignment(
            context, vmlinux_module_name
        )
        if not cls._validate_alignment_patterns(
            known_module_addresses, module_address_alignment
        ):
            vollog.warning(
                f"Module addresses aren't aligned to {module_address_alignment} bytes. "
                "Switching to 1 byte aligment scan method."
            )
            module_address_alignment = 1

        mkobj_offset = vmlinux.get_type("module").relative_child_offset("mkobj")
        mod_offset = vmlinux.get_type("module_kobject").relative_child_offset("mod")
        offset_to_mkobj_mod = mkobj_offset + mod_offset
        mod_member_template = vmlinux.get_type("module_kobject").vol.members["mod"][1]
        mod_size = mod_member_template.size
        mod_member_data_format = mod_member_template.data_format

        for module_addr in range(
            module_addr_min, module_addr_max, module_address_alignment
        ):
            if module_addr in known_module_addresses:
                continue

            try:
                # This is just a pre-filter. Module readability and consistency are verified in module.is_valid()
                self_referential_bytes = vmlinux_layer.read(
                    module_addr + offset_to_mkobj_mod, mod_size
                )
                self_referential = objects.convert_data_to_value(
                    self_referential_bytes, int, mod_member_data_format
                )
                if self_referential != module_addr:
                    continue
            except (
                exceptions.PagedInvalidAddressException,
                exceptions.InvalidAddressException,
            ):
                continue

            module = vmlinux.object("module", offset=module_addr, absolute=True)
            if module and module.is_valid():
                yield module

    @classmethod
    def get_lsmod_module_addresses(
        cls,
        context: interfaces.context.ContextInterface,
        vmlinux_module_name: str,
    ) -> Set[int]:
        """Obtain a set the known module addresses from linux.lsmod plugin

        Args:
            context: The context to retrieve required elements (layers, symbol tables) from
            vmlinux_module_name: The name of the kernel module on which to operate

        Returns:
            A set containing known kernel module addresses
        """
        vmlinux = context.modules[vmlinux_module_name]
        vmlinux_layer = context.layers[vmlinux.layer_name]

        known_module_addresses = {
            vmlinux_layer.canonicalize(module.vol.offset)
            for module in lsmod.Lsmod.list_modules(context, vmlinux_module_name)
        }
        return known_module_addresses

    def _generator(self):
        vmlinux_module_name = self.config["kernel"]
        known_module_addresses = self.get_lsmod_module_addresses(
            self.context, vmlinux_module_name
        )
        modules_memory_boundaries = self.get_modules_memory_boundaries(
            self.context, vmlinux_module_name
        )
        for module in self.get_hidden_modules(
            self.context,
            vmlinux_module_name,
            known_module_addresses,
            modules_memory_boundaries,
        ):
            module_addr = module.vol.offset
            module_name = module.get_name() or renderers.NotAvailableValue()
            fields = (format_hints.Hex(module_addr), module_name)
            yield (0, fields)

    def run(self):
        headers = [
            ("Address", format_hints.Hex),
            ("Name", str),
        ]
        return renderers.TreeGrid(headers, self._generator())
