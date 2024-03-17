# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

import logging
import os
from typing import Optional, Tuple, Type, Union

from volatility3.framework import constants, interfaces, exceptions
from volatility3.framework.automagic import symbol_cache, symbol_finder
from volatility3.framework.configuration import requirements
from volatility3.framework.layers import intel, scanners, arm
from volatility3.framework.symbols import linux

vollog = logging.getLogger(__name__)


class LinuxStacker(interfaces.automagic.StackerLayerInterface):
    stack_order = 35
    exclusion_list = ["mac", "windows"]
    join = interfaces.configuration.path_join

    @classmethod
    def stack(
        cls,
        context: interfaces.context.ContextInterface,
        layer_name: str,
        progress_callback: constants.ProgressCallback = None,
    ) -> Optional[interfaces.layers.DataLayerInterface]:
        """Attempts to identify linux within this layer."""
        # Version check the SQlite cache
        required = (1, 0, 0)
        if not requirements.VersionRequirement.matches_required(
            required, symbol_cache.SqliteCache.version
        ):
            vollog.info(
                f"SQLiteCache version not suitable: required {required} found {symbol_cache.SqliteCache.version}"
            )
            return None

        # Bail out by default unless we can stack properly
        layer = context.layers[layer_name]

        # Never stack on top of a linux layer
        # FIXME: Find a way to improve this check
        if isinstance(layer, intel.Intel) or isinstance(layer, arm.AArch64):
            return None

        identifiers_path = os.path.join(
            constants.CACHE_PATH, constants.IDENTIFIERS_FILENAME
        )
        linux_banners = symbol_cache.SqliteCache(
            identifiers_path
        ).get_identifier_dictionary(operating_system="linux")
        # If we have no banners, don't bother scanning
        if not linux_banners:
            vollog.info(
                "No Linux banners found - if this is a linux plugin, please check your symbol files location"
            )
            return None

        seen_banners = []
        mss = scanners.MultiStringScanner([x for x in linux_banners if x is not None])
        for _, banner in layer.scan(
            context=context, scanner=mss, progress_callback=progress_callback
        ):
            # No need to try stackers on the same banner more than once
            if banner in seen_banners:
                continue
            else:
                seen_banners.append(banner)

            vollog.debug(f"Identified banner: {repr(banner)}")

            isf_path = linux_banners.get(banner, None)
            if isf_path:
                table_name = context.symbol_space.free_table_name("LinuxStacker")
                table = linux.LinuxKernelIntermedSymbols(
                    context,
                    "temporary." + table_name,
                    name=table_name,
                    isf_url=isf_path,
                )
                context.symbol_space.append(table)
                new_layer_name = context.layers.free_layer_name("LinuxLayer")
                config_path = cls.join("LinuxHelper", new_layer_name)
                context.config[cls.join(config_path, "memory_layer")] = layer_name
                context.config[
                    cls.join(config_path, LinuxSymbolFinder.banner_config_key)
                ] = str(banner, "latin-1")

                linux_arch_stackers = [cls.intel_stacker, cls.aarch64_stacker]
                for linux_arch_stacker in linux_arch_stackers:
                    try:
                        layer = linux_arch_stacker(
                            context=context,
                            layer_name=layer_name,
                            table=table,
                            table_name=table_name,
                            config_path=config_path,
                            new_layer_name=new_layer_name,
                            banner=banner,
                            progress_callback=progress_callback,
                        )
                        if layer:
                            return layer
                    except Exception as e:
                        vollog.exception(e)

        vollog.debug("No suitable linux banner could be matched")
        return None

    @classmethod
    def intel_stacker(
        cls,
        context: interfaces.context.ContextInterface,
        layer_name: str,
        table: linux.LinuxKernelIntermedSymbols,
        table_name: str,
        config_path: str,
        new_layer_name: str,
        banner: str,
        progress_callback: constants.ProgressCallback = None,
    ) -> Union[intel.Intel, intel.Intel32e, None]:
        layer_class: Type = intel.Intel
        if "init_top_pgt" in table.symbols:
            layer_class = intel.Intel32e
            dtb_symbol_name = "init_top_pgt"
        elif "init_level4_pgt" in table.symbols:
            layer_class = intel.Intel32e
            dtb_symbol_name = "init_level4_pgt"
        else:
            dtb_symbol_name = "swapper_pg_dir"

        kaslr_shift, aslr_shift = cls.find_aslr(
            context,
            table_name,
            layer_name,
            layer_class,
            progress_callback=progress_callback,
        )

        dtb = cls.virtual_to_physical_address(
            table.get_symbol(dtb_symbol_name).address + kaslr_shift
        )

        # Build the new layer
        context.config[cls.join(config_path, "page_map_offset")] = dtb

        layer = layer_class(
            context,
            config_path=config_path,
            name=new_layer_name,
            metadata={"os": "Linux"},
        )
        layer.config["kernel_virtual_offset"] = aslr_shift
        linux_banner_address = table.get_symbol("linux_banner").address + aslr_shift
        test_banner_equality = cls.verify_translation_by_banner(
            context=context,
            layer=layer,
            layer_name=layer_name,
            linux_banner_address=linux_banner_address,
            target_banner=banner,
        )

        if layer and dtb and test_banner_equality:
            vollog.debug(f"DTB was found at: 0x{dtb:0x}")
            vollog.debug("Intel image found")
            return layer
        else:
            layer.destroy()

        return None

    @classmethod
    def aarch64_stacker(
        cls,
        context: interfaces.context.ContextInterface,
        layer_name: str,
        table: linux.LinuxKernelIntermedSymbols,
        table_name: str,
        config_path: str,
        new_layer_name: str,
        banner: bytes,
        progress_callback: constants.ProgressCallback = None,
    ) -> Optional[arm.AArch64]:
        layer_class = arm.AArch64
        kaslr_shift, aslr_shift = cls.find_aslr(
            context,
            table_name,
            layer_name,
            layer_class,
            progress_callback=progress_callback,
        )
        dtb = table.get_symbol("swapper_pg_dir").address + kaslr_shift
        context.config[cls.join(config_path, "page_map_offset")] = dtb
        context.config[cls.join(config_path, "page_map_offset_kernel")] = dtb
        kernel_endianness = table.get_type("pointer").vol.data_format.byteorder
        context.config[cls.join(config_path, "kernel_endianness")] = kernel_endianness

        # CREDIT : https://github.com/crash-utility/crash/blob/28891d1127542dbb2d5ba16c575e14e741ed73ef/arm64.c#L941
        kernel_flags = 0
        if "_kernel_flags_le" in table.symbols:
            kernel_flags = table.get_symbol("_kernel_flags_le").address
        if "_kernel_flags_le_hi32" in table.symbols:
            kernel_flags |= table.get_symbol("_kernel_flags_le_hi32").address << 32
        if "_kernel_flags_le_lo32" in table.symbols:
            kernel_flags |= table.get_symbol("_kernel_flags_le_lo32").address

        # https://www.kernel.org/doc/Documentation/arm64/booting.txt
        page_size_kernel_space_bit = (kernel_flags >> 1) & 3
        page_size_kernel_space_candidates = (
            [4**page_size_kernel_space_bit]
            if 1 <= page_size_kernel_space_bit <= 3
            else [4, 16, 64]
        )

        linux_banner_address = table.get_symbol("linux_banner").address + aslr_shift
        # Linux source : v6.7/source/arch/arm64/include/asm/memory.h#L186 - v5.7/source/arch/arm64/include/asm/memory.h#L160
        if "vabits_actual" in table.symbols:
            vabits_actual_phys_addr = (
                table.get_symbol("vabits_actual").address + kaslr_shift
            )
            # Linux source : v6.7/source/arch/arm64/Kconfig#L1263, VA_BITS
            va_bits = int.from_bytes(
                context.layers[layer_name].read(vabits_actual_phys_addr, 8),
                kernel_endianness,
            )
        else:
            """
            Count leftmost bits equal to 1, deduce number of used bits for virtual addressing.
            Example :
                linux_banner_address = 0xffffffd733aae820 = 0b1111111111111111111111111101011100110011101010101110100000100000
                va_bits = (linux_banner_address ^ (2**64 - 1)).bit_length() + 1 = 39
            """
            va_bits = (linux_banner_address ^ (2**64 - 1)).bit_length() + 1

        """
        Determining the number of useful bits in virtual addresses (VA_BITS)
        is not straightforward, and not available in the kernel symbols.
        Calculation by masking works great, but not in every case, due to the AArch64 memory layout,
        sometimes pushing kernel addresses "too far" from the TTB1 start.
        See https://www.kernel.org/doc/html/v5.5/arm64/memory.html.
        Errors are by 1 or 2 bits, so we can try va_bits - {1,2,3}.
        Example, assuming the good va_bits value is 39 :
            # Case where calculation was correct : 1 iteration
            va_bits_candidates = [**39**, 38, 37, 36]
            # Case where calculation is off by 1 : 2 iterations
            va_bits_candidates = [40, **39**, 38, 37]
        """
        va_bits_candidates = [va_bits] + [va_bits + i for i in range(-1, -4, -1)]
        for va_bits in va_bits_candidates:
            tcr_el1_t1sz = 64 - va_bits
            # T1SZ is considered equal to T0SZ
            context.config[cls.join(config_path, "tcr_el1_t1sz")] = tcr_el1_t1sz
            context.config[cls.join(config_path, "tcr_el1_t0sz")] = tcr_el1_t1sz

            # If "_kernel_flags_le*" aren't in the symbols, we can still do a quick bruteforce on [4,16,64] page sizes
            # False positives cannot happen, as translation indexes will be off on a wrong page size
            for page_size_kernel_space in page_size_kernel_space_candidates:
                # Kernel space page size is considered equal to the user space page size
                context.config[cls.join(config_path, "page_size_kernel_space")] = (
                    page_size_kernel_space
                )
                context.config[cls.join(config_path, "page_size_user_space")] = (
                    page_size_kernel_space
                )
                # Build layer
                layer = layer_class(
                    context,
                    config_path=config_path,
                    name=new_layer_name,
                    metadata={"os": "Linux"},
                )
                layer.config["kernel_virtual_offset"] = aslr_shift

                test_banner_equality = cls.verify_translation_by_banner(
                    context=context,
                    layer=layer,
                    layer_name=layer_name,
                    linux_banner_address=linux_banner_address,
                    target_banner=banner,
                )

                if layer and dtb and test_banner_equality:
                    vollog.debug(f"Kernel DTB was found at: 0x{dtb:0x}")
                    vollog.debug("AArch64 image found")
                    return layer
                else:
                    layer.destroy()

        return None

    @classmethod
    def verify_translation_by_banner(
        cls,
        context: interfaces.context.ContextInterface,
        layer,
        layer_name: str,
        linux_banner_address: int,
        target_banner: bytes,
    ) -> bool:
        """Determine if a stacked layer is correct or a false positive, by calling the underlying
        _translate method against the linux_banner symbol virtual address. Then, compare it with
        the detected banner to verify the correct translation.
        """

        try:
            banner_phys_address = layer._translate(linux_banner_address)[0]
            banner_value = context.layers[layer_name].read(
                banner_phys_address, len(target_banner)
            )
        except exceptions.InvalidAddressException as e:
            vollog.log(
                constants.LOGLEVEL_VVVV,
                'Cannot translate "linux_banner" symbol virtual address.',
            )
            return False

        if not banner_value == target_banner:
            vollog.error(
                f"Mismatch between scanned and virtually translated linux banner : {target_banner} != {banner_value}."
            )
            return False

        return True

    @classmethod
    def find_aslr(
        cls,
        context: interfaces.context.ContextInterface,
        symbol_table: str,
        layer_name: str,
        layer_class,
        progress_callback: constants.ProgressCallback = None,
    ) -> Tuple[int, int]:
        """Determines the offset of the actual DTB in physical space and its
        symbol offset."""
        init_task_symbol = symbol_table + constants.BANG + "init_task"
        init_task_json_address = context.symbol_space.get_symbol(
            init_task_symbol
        ).address
        swapper_signature = rb"swapper(\/0|\x00\x00)\x00\x00\x00\x00\x00\x00"
        module = context.module(symbol_table, layer_name, 0)
        address_mask = context.symbol_space[symbol_table].config.get(
            "symbol_mask", None
        )

        task_symbol = module.get_type("task_struct")
        comm_child_offset = task_symbol.relative_child_offset("comm")

        for offset in context.layers[layer_name].scan(
            scanner=scanners.RegExScanner(swapper_signature),
            context=context,
            progress_callback=progress_callback,
        ):
            init_task_address = offset - comm_child_offset
            init_task = module.object(
                object_type="task_struct", offset=init_task_address, absolute=True
            )
            if init_task.pid != 0:
                continue
            elif (
                init_task.has_member("state")
                and init_task.state.cast("unsigned int") != 0
            ):
                continue

            # This we get for free
            aslr_shift = (
                init_task.files.cast("long unsigned int")
                - module.get_symbol("init_files").address
            )
            if layer_class == arm.AArch64:
                kaslr_shift = init_task_address - init_task_json_address
            else:
                kaslr_shift = init_task_address - cls.virtual_to_physical_address(
                    init_task_json_address
                )
            if address_mask:
                aslr_shift = aslr_shift & address_mask

            if aslr_shift & 0xFFF != 0 or kaslr_shift & 0xFFF != 0:
                continue
            vollog.debug(
                "Linux ASLR shift values determined: physical {:0x} virtual {:0x}".format(
                    kaslr_shift, aslr_shift
                )
            )
            return kaslr_shift, aslr_shift

        # We don't throw an exception, because we may legitimately not have an ASLR shift, but we report it
        vollog.debug("Scanners could not determine any ASLR shifts, using 0 for both")
        return 0, 0

    @classmethod
    def virtual_to_physical_address(cls, addr: int) -> int:
        """Converts a virtual linux address to a physical one (does not account
        of ASLR)"""
        if addr > 0xFFFFFFFF80000000:
            return addr - 0xFFFFFFFF80000000
        return addr - 0xC0000000


class LinuxSymbolFinder(symbol_finder.SymbolFinder):
    """Linux symbol loader based on uname signature strings."""

    banner_config_key = "kernel_banner"
    operating_system = "linux"
    symbol_class = "volatility3.framework.symbols.linux.LinuxKernelIntermedSymbols"
    find_aslr = lambda cls, *args: LinuxStacker.find_aslr(*args)[1]
    exclusion_list = ["mac", "windows"]
