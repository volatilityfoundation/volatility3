# This file is Copyright 2024 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
import re
import functools
import logging
import contextlib
from typing import List, Iterable
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
            requirements.BooleanRequirement(
                name="fast",
                description="Fast scan method. Recommended only for kernels 4.2 and above",
                optional=True,
                default=False,
            ),
        ]

    def _get_modules_memory_boundaries(self, vmlinux):
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

    def _get_module_state_values_bytes(
        self,
        context: interfaces.context.ContextInterface,
        vmlinux_module_name: str,
    ) -> List[bytes]:
        """Retrieve the module state values bytes by introspecting its enum type

        Args:
            context: The context to retrieve required elements (layers, symbol tables) from
            vmlinux_module_name: The name of the kernel module on which to operate

        Returns:
            A list with the module state values bytes
        """
        vmlinux = context.modules[vmlinux_module_name]
        module_state_type_template = vmlinux.get_type("module").vol.members["state"][1]
        data_format = module_state_type_template.base_type.vol.data_format
        values = module_state_type_template.choices.values()
        values_bytes = [
            objects.convert_value_to_data(value, int, data_format)
            for value in sorted(values)
        ]
        return values_bytes

    def get_hidden_modules_vol2(
        self,
        context: interfaces.context.ContextInterface,
        vmlinux_module_name: str,
        known_module_addresses,
        modules_memory_boundaries: tuple,
    ) -> Iterable[interfaces.objects.ObjectInterface]:
        """Enumerate hidden modules using the traditional implementation.

        This is a port of the Volatility2 plugin, with minor code improvements.

        Args:
            context: The context to retrieve required elements (layers, symbol tables) from
            vmlinux_module_name: The name of the kernel module on which to operate
        Yields:
            module objects
        """
        vmlinux = context.modules[vmlinux_module_name]
        vmlinux_layer = context.layers[vmlinux.layer_name]

        check_nums = (
            3000,
            2800,
            2700,
            2500,
            2300,
            2100,
            2000,
            1500,
            1300,
            1200,
            1024,
            512,
            256,
            128,
            96,
            64,
            48,
            32,
            24,
        )
        modules_addr_min, modules_addr_max = modules_memory_boundaries
        modules_addr_min = modules_addr_min & ~0xFFF
        modules_addr_max = (modules_addr_max & ~0xFFF) + vmlinux_layer.page_size

        check_bufs = []
        replace_bufs = []
        minus_size = vmlinux.get_type("pointer").size
        null_pointer_bytes = b"\x00" * minus_size
        for num in check_nums:
            check_bufs.append(b"\x00" * num)
            replace_bufs.append((b"\xff" * (num - minus_size)) + null_pointer_bytes)

        all_ffs = b"\xff" * 4096
        scan_list = []
        for page_addr in range(
            modules_addr_min, modules_addr_max, vmlinux_layer.page_size
        ):
            content_fixed = all_ffs
            with contextlib.suppress(
                exceptions.InvalidAddressException,
                exceptions.PagedInvalidAddressException,
            ):
                content = vmlinux_layer.read(page_addr, vmlinux_layer.page_size)

                all_nulls = all(x == 0 for x in content)
                if content and not all_nulls:
                    content_fixed = content
                    for check_bytes, replace_bytes in zip(check_bufs, replace_bufs):
                        content_fixed = content_fixed.replace(
                            check_bytes, replace_bytes
                        )

            scan_list.append(content_fixed)

        scan_buf = b"".join(scan_list)
        del scan_list

        module_state_values_bytes = self._get_module_state_values_bytes(
            context, vmlinux_module_name
        )
        values_bytes_pattern = b"|".join(module_state_values_bytes)
        # f'strings cannot be combined with bytes literals
        for cur_addr in re.finditer(b"(?=(%s))" % values_bytes_pattern, scan_buf):
            module_addr = modules_addr_min + cur_addr.start()

            if module_addr in known_module_addresses:
                continue

            module = vmlinux.object("module", offset=module_addr, absolute=True)
            if module and module.is_valid():
                yield module

    @functools.cached_property
    def module_address_alignment(self) -> int:
        """Obtain the module memory address alignment. This is only used with the fast scan method.

        struct module is aligned to the L1 cache line, which is typically 64 bytes for most
        common i386/AMD64/ARM64 configurations. In some cases, it can be 128 bytes, but this
        will still work.

        Returns:
            The struct module alignment
        """
        # FIXME: When dwarf2json/ISF supports type alignments. Read it directly from the type metadata
        # The cached_property won't provide any benefits until then
        return 64

    def get_hidden_modules_fast(
        self,
        context: interfaces.context.ContextInterface,
        vmlinux_module_name: str,
        known_module_addresses,
        modules_memory_boundaries: tuple,
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
        Yields:
            module objects
        """
        vmlinux = context.modules[vmlinux_module_name]
        vmlinux_layer = context.layers[vmlinux.layer_name]

        module_addr_min, module_addr_max = modules_memory_boundaries

        module_state_values_bytes = self._get_module_state_values_bytes(
            context, vmlinux_module_name
        )

        for module_addr in range(
            module_addr_min, module_addr_max, self.module_address_alignment
        ):
            if module_addr in known_module_addresses:
                continue

            try:
                # This is just a pre-filter. Module readability and consistency are verified in module.is_valid()
                module_state_bytes = vmlinux_layer.read(
                    module_addr, len(module_state_values_bytes[0])
                )
                if module_state_bytes not in module_state_values_bytes:
                    continue
            except (
                exceptions.PagedInvalidAddressException,
                exceptions.InvalidAddressException,
            ):
                continue

            module = vmlinux.object("module", offset=module_addr, absolute=True)
            if module and module.is_valid():
                yield module

    def _validate_alignment_patterns(self, addresses: Iterable[int]) -> bool:
        """Check if the memory addresses meet our alignments patterns

        Args:
            addresses: Iterable with the address values

        Returns:
            True if all the addresses meet the alignment
        """
        return all(addr % self.module_address_alignment == 0 for addr in addresses)

    def get_hidden_modules(
        self,
        context: interfaces.context.ContextInterface,
        vmlinux_module_name: str,
    ) -> Iterable[interfaces.objects.ObjectInterface]:
        """Enumerate hidden modules

        Args:
            context: The context to retrieve required elements (layers, symbol tables) from
            vmlinux_module_name: The name of the kernel module on which to operate
        Yields:
            module objects
        """
        vmlinux = context.modules[vmlinux_module_name]
        vmlinux_layer = context.layers[vmlinux.layer_name]

        known_module_addresses = {
            vmlinux_layer.canonicalize(module.vol.offset)
            for module in lsmod.Lsmod.list_modules(context, vmlinux_module_name)
        }

        modules_memory_boundaries = self._get_modules_memory_boundaries(vmlinux)

        if self.config.get("fast"):
            if self._validate_alignment_patterns(known_module_addresses):
                scan_method = self.get_hidden_modules_fast
            else:
                vollog.warning(
                    f"Module addresses aren't aligned to {self.module_address_alignment} bytes. "
                    "Switching to the traditional scan method."
                )
                scan_method = self.get_hidden_modules_vol2
        else:
            scan_method = self.get_hidden_modules_vol2

        yield from scan_method(
            context,
            vmlinux_module_name,
            known_module_addresses,
            modules_memory_boundaries,
        )

    def _generator(self):
        vmlinux_module_name = self.config["kernel"]
        for module in self.get_hidden_modules(self.context, vmlinux_module_name):
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
