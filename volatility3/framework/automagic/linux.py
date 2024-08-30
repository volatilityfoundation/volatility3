# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

import logging
import os
import json
import struct
import functools
from typing import Optional, Tuple, Union, Dict

from volatility3.framework import constants, interfaces, exceptions
from volatility3.framework.automagic import symbol_cache, symbol_finder
from volatility3.framework.configuration import requirements
from volatility3.framework.layers import intel, scanners, arm
from volatility3.framework.symbols import linux
from volatility3.framework.interfaces.configuration import path_join

vollog = logging.getLogger(__name__)


class LinuxStacker(interfaces.automagic.StackerLayerInterface):
    stack_order = 35
    exclusion_list = ["mac", "windows"]

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
                config_path = path_join("LinuxHelper", new_layer_name)
                context.config[path_join(config_path, "memory_layer")] = layer_name
                context.config[
                    path_join(config_path, LinuxSymbolFinder.banner_config_key)
                ] = str(banner, "latin-1")

                linux_arch_stackers = [LinuxIntelSubStacker, LinuxAArch64SubStacker]
                for linux_arch_stacker in linux_arch_stackers:
                    try:
                        sub_stacker = linux_arch_stacker(cls)
                        layer = sub_stacker.stack(
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

        vollog.debug("No suitable Linux banner could be matched")
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
        except exceptions.InvalidAddressException:
            vollog.log(
                constants.LOGLEVEL_VVVV,
                'Cannot translate "linux_banner" symbol virtual address.',
            )
            return False

        if not banner_value == target_banner:
            vollog.log(
                constants.LOGLEVEL_VV,
                f"Mismatch between scanned and virtually translated linux banner : {target_banner} != {banner_value}.",
            )
            return False

        return True

    @classmethod
    @functools.lru_cache()
    def find_aslr(
        cls,
        context: interfaces.context.ContextInterface,
        symbol_table: str,
        layer_name: str,
        progress_callback: constants.ProgressCallback = None,
    ) -> Tuple[int, int]:
        """Determines the offset of the actual DTB in physical space and its
        symbol offset."""

        module = context.module(symbol_table, layer_name, 0)
        swapper_signature = rb"swapper(\/0|\x00\x00)\x00\x00\x00\x00\x00\x00"
        address_mask = context.symbol_space[symbol_table].config.get(
            "symbol_mask", None
        )
        init_task_symbol = symbol_table + constants.BANG + "init_task"
        init_task_json_address = context.symbol_space.get_symbol(
            init_task_symbol
        ).address
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

            # ASLR calculation
            aslr_shift = (
                int.from_bytes(
                    init_task.files.cast("bytes", length=init_task.files.vol.size),
                    byteorder=init_task.files.vol.data_format.byteorder,
                )
                - module.get_symbol("init_files").address
            )
            if address_mask:
                aslr_shift = aslr_shift & address_mask

            # KASLR calculation (physical symbol address - virtual symbol address)
            kaslr_shift = init_task_address - init_task_json_address

            # Check ASLR and KASLR candidates
            if aslr_shift & 0xFFF != 0 or kaslr_shift & 0xFFF != 0:
                continue
            vollog.debug(
                f"Linux addresses shift values determined: KASLR (physical) = {hex(kaslr_shift)}, ASLR (virtual) = {hex(aslr_shift)}"
            )
            return kaslr_shift, aslr_shift

        # We don't throw an exception, because we may legitimately not have an ASLR shift, but we report it
        vollog.debug("Scanners could not determine any ASLR shifts, using 0 for both")
        return 0, 0


class LinuxIntelSubStacker:
    __START_KERNEL_map_x64 = 0xFFFFFFFF80000000
    __START_KERNEL_map_x86 = 0xC0000000

    def __init__(self, parent_stacker: LinuxStacker) -> None:
        self.parent_stacker = parent_stacker

    def stack(
        self,
        context: interfaces.context.ContextInterface,
        layer_name: str,
        table: linux.LinuxKernelIntermedSymbols,
        table_name: str,
        config_path: str,
        new_layer_name: str,
        banner: str,
        progress_callback: constants.ProgressCallback = None,
    ) -> Union[intel.Intel, intel.Intel32e, None]:
        layer_class = intel.Intel

        if "init_top_pgt" in table.symbols:
            layer_class = intel.Intel32e
            dtb_symbol_name = "init_top_pgt"
        elif "init_level4_pgt" in table.symbols:
            layer_class = intel.Intel32e
            dtb_symbol_name = "init_level4_pgt"
        else:
            dtb_symbol_name = "swapper_pg_dir"

        kaslr_shift, aslr_shift = self.parent_stacker.find_aslr(
            context,
            table_name,
            layer_name,
            progress_callback=progress_callback,
        )

        dtb = table.get_symbol(dtb_symbol_name).address + kaslr_shift

        # Build the new layer
        context.config[path_join(config_path, "page_map_offset")] = dtb
        layer = layer_class(
            context,
            config_path=config_path,
            name=new_layer_name,
            metadata={"os": "Linux"},
        )
        layer.config["kernel_virtual_offset"] = aslr_shift

        # Verify layer by translating the "linux_banner" symbol virtual address
        linux_banner_address = table.get_symbol("linux_banner").address + aslr_shift
        test_banner_equality = self.parent_stacker.verify_translation_by_banner(
            context=context,
            layer=layer,
            layer_name=layer_name,
            linux_banner_address=linux_banner_address,
            target_banner=banner,
        )

        if layer and dtb and test_banner_equality:
            vollog.debug(f"DTB was found at: {hex(dtb)}")
            vollog.debug("Intel image found")
            return layer
        else:
            layer.destroy()

        return None

    @classmethod
    def virtual_to_physical_address(cls, addr: int) -> int:
        """Converts a virtual Intel Linux address to a physical one (does not account
        of ASLR)"""
        # Detect x64/x86 address space
        if addr > cls.__START_KERNEL_map_x64:
            return addr - cls.__START_KERNEL_map_x64
        return addr - cls.__START_KERNEL_map_x86


class LinuxAArch64SubStacker:
    # https://developer.arm.com/documentation/ddi0601/latest/AArch64-Registers/
    # CPU register, bound to its attribute name in the "cpuinfo_arm64" kernel struct
    _optional_cpu_registers = {
        arm.AArch64RegMap.ID_AA64MMFR1_EL1.__name__: "reg_id_aa64mmfr1"
    }

    def __init__(self, parent_stacker: LinuxStacker) -> None:
        self.parent_stacker = parent_stacker

    def stack(
        self,
        context: interfaces.context.ContextInterface,
        layer_name: str,
        table: linux.LinuxKernelIntermedSymbols,
        table_name: str,
        config_path: str,
        new_layer_name: str,
        banner: bytes,
        progress_callback: constants.ProgressCallback = None,
    ) -> Optional[arm.LinuxAArch64]:
        layer_class = arm.LinuxAArch64
        kaslr_shift, aslr_shift = self.parent_stacker.find_aslr(
            context,
            table_name,
            layer_name,
            progress_callback=progress_callback,
        )
        dtb = table.get_symbol("swapper_pg_dir").address + kaslr_shift
        ttbr1_el1 = arm.set_reg_bits(dtb, arm.AArch64RegMap.TTBR1_EL1.BADDR)
        context.config[path_join(config_path, "page_map_offset")] = dtb
        entry_format = (
            "<"
            if table.get_type("pointer").vol.data_format.byteorder == "little"
            else "big"
        )
        entry_format += (
            "Q" if table.get_type("pointer").vol.data_format.length == 8 else "I"
        )
        context.config[path_join(config_path, "entry_format")] = entry_format

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
        va_bits = 0
        if "vabits_actual" in table.symbols:
            vabits_actual_phys_addr = (
                table.get_symbol("vabits_actual").address + kaslr_shift
            )
            # Linux source : v6.7/source/arch/arm64/Kconfig#L1263, VA_BITS
            (va_bits,) = struct.unpack(
                entry_format,
                context.layers[layer_name].read(vabits_actual_phys_addr, 8),
            )
        if not va_bits:
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
            cpu_registers = {}
            tcr_el1 = 0
            # T1SZ is considered to equal to T0SZ
            tcr_el1 = arm.set_reg_bits(
                64 - va_bits, arm.AArch64RegMap.TCR_EL1.T1SZ, tcr_el1
            )
            tcr_el1 = arm.set_reg_bits(
                64 - va_bits, arm.AArch64RegMap.TCR_EL1.T0SZ, tcr_el1
            )

            # If "_kernel_flags_le*" aren't in the symbols, we can still do a quick bruteforce on [4,16,64] page sizes
            # False positives cannot happen, as translation indexes will be off on a wrong page size
            for page_size_kernel_space in page_size_kernel_space_candidates:
                # Kernel space page size is considered equal to the user space page size
                tcr_el1_tg1 = arm.AArch64RegFieldValues._get_ttbr1_el1_granule_size(
                    page_size_kernel_space, True
                )
                tcr_el1_tg0 = arm.AArch64RegFieldValues._get_ttbr0_el1_granule_size(
                    page_size_kernel_space, True
                )
                tcr_el1 = arm.set_reg_bits(
                    tcr_el1_tg1, arm.AArch64RegMap.TCR_EL1.TG1, tcr_el1
                )
                tcr_el1 = arm.set_reg_bits(
                    tcr_el1_tg0, arm.AArch64RegMap.TCR_EL1.TG0, tcr_el1
                )

                cpu_registers[arm.AArch64RegMap.TCR_EL1.__name__] = tcr_el1
                cpu_registers[arm.AArch64RegMap.TTBR1_EL1.__name__] = ttbr1_el1
                context.config[path_join(config_path, "cpu_registers")] = json.dumps(
                    cpu_registers
                )
                # Build layer
                layer = layer_class(
                    context,
                    config_path=config_path,
                    name=new_layer_name,
                    metadata={"os": "Linux"},
                )
                layer.config["kernel_virtual_offset"] = aslr_shift

                test_banner_equality = self.parent_stacker.verify_translation_by_banner(
                    context=context,
                    layer=layer,
                    layer_name=layer_name,
                    linux_banner_address=linux_banner_address,
                    target_banner=banner,
                )

                if layer and dtb and test_banner_equality:
                    try:
                        optional_cpu_registers = self.extract_cpu_registers(
                            context=context,
                            layer_name=layer_name,
                            table_name=table_name,
                            kaslr_shift=kaslr_shift,
                        )
                        cpu_registers.update(optional_cpu_registers)
                        layer.config["cpu_registers"] = json.dumps(cpu_registers)
                    except exceptions.SymbolError as e:
                        vollog.log(constants.LOGLEVEL_VVV, e, exc_info=True)
                    vollog.debug(f"DTB was found at: {hex(dtb)}")
                    vollog.debug("AArch64 image found")
                    return layer
                else:
                    layer.destroy()

        return None

    @classmethod
    def extract_cpu_registers(
        cls,
        context: interfaces.context.ContextInterface,
        layer_name: str,
        table_name: str,
        kaslr_shift: int,
    ) -> Dict[str, int]:

        tmp_kernel_module = context.module(table_name, layer_name, kaslr_shift)
        boot_cpu_data_struct = tmp_kernel_module.object_from_symbol("boot_cpu_data")
        cpu_registers = {}
        for cpu_reg, cpu_reg_attribute_name in cls._optional_cpu_registers.items():
            try:
                cpu_reg_value = getattr(boot_cpu_data_struct, cpu_reg_attribute_name)
                cpu_registers[cpu_reg] = cpu_reg_value
            except AttributeError:
                vollog.log(
                    constants.LOGLEVEL_VVV,
                    f"boot_cpu_data struct does not include the {cpu_reg_attribute_name} field.",
                )

        return cpu_registers


class LinuxSymbolFinder(symbol_finder.SymbolFinder):
    """Linux symbol loader based on uname signature strings."""

    banner_config_key = "kernel_banner"
    operating_system = "linux"
    # TODO: Avoid hardcoded strings
    symbol_class = "volatility3.framework.symbols.linux.LinuxKernelIntermedSymbols"
    find_aslr = lambda cls, *args: LinuxStacker.find_aslr(*args)[1]
    exclusion_list = ["mac", "windows"]
