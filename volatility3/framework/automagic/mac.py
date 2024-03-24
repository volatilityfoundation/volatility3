# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

import logging
import os
import struct
from typing import Optional

from volatility3.framework import constants, exceptions, interfaces
from volatility3.framework.automagic import symbol_cache, symbol_finder
from volatility3.framework.configuration import requirements
from volatility3.framework.layers import intel, scanners
from volatility3.framework.symbols import mac

vollog = logging.getLogger(__name__)


class MacIntelStacker(interfaces.automagic.StackerLayerInterface):
    stack_order = 35
    exclusion_list = ["windows", "linux"]
    join = interfaces.configuration.path_join
    _KERNEL_MIN_ADDRESS = 0xFFFFFF8000000000

    @classmethod
    def stack(
        cls,
        context: interfaces.context.ContextInterface,
        layer_name: str,
        progress_callback: constants.ProgressCallback = None,
    ) -> Optional[interfaces.layers.DataLayerInterface]:
        """Attempts to identify mac within this layer."""
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
        new_layer = None

        # Never stack on top of an intel layer
        # FIXME: Find a way to improve this check
        if isinstance(layer, intel.Intel):
            return None

        identifiers_path = os.path.join(
            constants.CACHE_PATH, constants.IDENTIFIERS_FILENAME
        )
        mac_banners = symbol_cache.SqliteCache(
            identifiers_path
        ).get_identifier_dictionary(operating_system="mac")
        # If we have no banners, don't bother scanning
        if not mac_banners:
            vollog.info(
                "No Mac banners found - if this is a mac plugin, please check your symbol files location"
            )
            return None

        seen_banners = []
        mss = scanners.MultiStringScanner([x for x in mac_banners if x])
        for banner_offset, banner in layer.scan(
            context=context, scanner=mss, progress_callback=progress_callback
        ):
            # No need to try stackers on the same banner more than once
            if banner in seen_banners:
                continue
            else:
                seen_banners.append(banner)
            dtb = None
            vollog.debug(f"Identified banner: {repr(banner)}")

            isf_path = mac_banners.get(banner, None)
            if isf_path:
                table_name = context.symbol_space.free_table_name("MacintelStacker")
                symbol_table = mac.MacKernelIntermedSymbols(
                    context=context,
                    config_path=cls.join("temporary", table_name),
                    name=table_name,
                    isf_url=isf_path,
                )
                context.symbol_space.append(symbol_table)
                kaslr_shift = cls.find_aslr(
                    context=context,
                    symbol_table=table_name,
                    layer_name=layer_name,
                    compare_banner=banner,
                    compare_banner_offset=banner_offset,
                    progress_callback=progress_callback,
                )
                if kaslr_shift == 0:
                    vollog.log(
                        constants.LOGLEVEL_VVV,
                        f"Unable to calculate a valid KASLR shift for banner : {banner}",
                    )
                    continue

                idlepml4_json_address = symbol_table.get_symbol("IdlePML4").address
                idlepml4_ptr = idlepml4_json_address + kaslr_shift
                try:
                    idlepml4_raw = context.layers[layer_name].read(
                        cls.virtual_to_physical_address(idlepml4_ptr), 4
                    )
                except exceptions.InvalidAddressException:
                    vollog.log(
                        constants.LOGLEVEL_VVVV,
                        f"Skipping invalid IdlePML4 pointer: {hex(idlepml4_ptr)}",
                    )
                    continue

                dtb_candidate = struct.unpack("<I", idlepml4_raw)[0]
                if dtb_candidate % 4096:
                    vollog.log(
                        constants.LOGLEVEL_VVV,
                        f"Skipping non-page aligned DTB: {hex(dtb_candidate)}",
                    )
                    continue
                dtb = dtb_candidate
                # Build the new layer
                new_layer_name = context.layers.free_layer_name("IntelLayer")
                config_path = cls.join("automagic", "MacIntelHelper", new_layer_name)
                context.config[cls.join(config_path, "memory_layer")] = layer_name
                context.config[cls.join(config_path, "page_map_offset")] = dtb
                context.config[
                    cls.join(config_path, MacSymbolFinder.banner_config_key)
                ] = str(banner, "latin-1")

                layer_class = intel.Intel32e
                # If an mh_fileset_config exists, this means the KernelCache is in an MH_FILESET format
                mh_fileset_config = context.config.branch(
                    cls.join(MacSymbolFinder.mh_fileset_config_path_prefix, table_name)
                )
                if mh_fileset_config:
                    for key, value in mh_fileset_config.items():
                        context.config[cls.join(config_path, key)] = value
                    layer_class = intel.MacIntelMhFilesetKernelCache

                new_layer = layer_class(
                    context,
                    config_path=config_path,
                    name=new_layer_name,
                    metadata={"os": "mac"},
                )
                new_layer.config["kernel_virtual_offset"] = kaslr_shift

            if new_layer and dtb:
                vollog.debug(f"DTB was found at: {hex(dtb)}")
                return new_layer
        vollog.debug("No suitable mac banner could be matched")
        return None

    @classmethod
    def find_aslr(
        cls,
        context: interfaces.context.ContextInterface,
        symbol_table: str,
        layer_name: str,
        compare_banner: str = "",
        compare_banner_offset: int = 0,
        progress_callback: constants.ProgressCallback = None,
    ) -> int:
        """Determines the offset of the actual DTB in physical space and its
        symbol offset."""

        banner_major_version, banner_minor_version = [
            int(x) for x in compare_banner[22:].split(b".")[0:2]
        ]

        """
        References :
         - https://github.com/apple-open-source/macos/blob/14.3/xnu/osfmk/x86_64/lowmem_vectors.c#L78
         - https://github.com/apple-open-source/macos/blob/14.3/xnu/osfmk/x86_64/lowglobals.h#L50
        """

        symbol_table_object: mac.MacKernelIntermedSymbols = context.symbol_space[
            symbol_table
        ]
        lowglo_json_address = symbol_table_object.get_symbol("lowGlo").address
        lowglo_phys_offset = cls.virtual_to_physical_address(lowglo_json_address)

        aslr_shift = 0
        for offset in cls._lowglo_scan_generator(
            context, layer_name, progress_callback
        ):

            aslr_shift_candidate = offset - lowglo_phys_offset
            if aslr_shift_candidate & 0xFFF != 0:
                continue

            # We can use the convenient module methods, with virtual addresses in physical space,
            # because the shift is constant and known.
            module = context.module(
                symbol_table,
                layer_name,
                aslr_shift_candidate - cls._KERNEL_MIN_ADDRESS,
            )

            # https://github.com/apple-open-source/macos/blob/14.3/xnu/osfmk/i386/i386_vm_init.c#L282
            vm_kernel_slide_candidate = module.object_from_symbol("vm_kernel_slide")
            mh_fileset_kernel_cache_check = False
            try:
                mh_fileset_kernel_cache_check = cls.detect_mh_fileset_kernel_cache(
                    context,
                    symbol_table,
                    layer_name,
                    aslr_shift_candidate,
                )
            except exceptions.SymbolError as e:
                vollog.log(constants.LOGLEVEL_VVVV, e)
            except exceptions.InvalidAddressException:
                continue

            if mh_fileset_kernel_cache_check:
                vm_kernel_slide_candidate = (
                    cls.vm_kernel_slide_kernel_cache_calculations(
                        context,
                        symbol_table,
                        layer_name,
                        aslr_shift_candidate,
                        vm_kernel_slide_candidate,
                    )
                )

            if vm_kernel_slide_candidate & 0xFFF != 0:
                continue

            # Banner related symbols have been slid by vm_kernel_slide
            module_vm_kernel_slide = context.module(
                symbol_table,
                layer_name,
                vm_kernel_slide_candidate - cls._KERNEL_MIN_ADDRESS,
            )

            # Verify ASLR with major and minor versions of banner
            major = module_vm_kernel_slide.object_from_symbol("version_major")
            if major != banner_major_version:
                continue

            minor = module_vm_kernel_slide.object_from_symbol("version_minor")
            if minor != banner_minor_version:
                continue

            if mh_fileset_kernel_cache_check:
                # Kernel __TEXT section start and end
                stext = module.object_from_symbol("stext")
                etext = module.object_from_symbol("etext")

                config_path = cls.join(
                    MacSymbolFinder.mh_fileset_config_path_prefix, symbol_table
                )
                context.config[cls.join(config_path, "vm_kernel_slide")] = (
                    vm_kernel_slide_candidate
                )
                context.config[cls.join(config_path, "kernel_start")] = stext
                context.config[cls.join(config_path, "kernel_end")] = etext

            aslr_shift = aslr_shift_candidate
            vollog.log(
                constants.LOGLEVEL_VVVV,
                f'Mac find_aslr found "vm_kernel_slide" to be: {hex(vm_kernel_slide_candidate)}',
            )

            break
        vollog.log(
            constants.LOGLEVEL_VVVV,
            f"Mac find_aslr returned: {hex(aslr_shift)}",
        )
        return aslr_shift

    @classmethod
    def vm_kernel_slide_kernel_cache_calculations(
        cls,
        context: interfaces.context.ContextInterface,
        symbol_table: str,
        layer_name: str,
        aslr_shift: int,
        vm_kernel_slide: int,
    ) -> int:
        """
        Effective kernel slide calculation necessites post actions, as hinted here :
         - https://github.com/apple-open-source/macos/blob/ea4cd5a06831aca49e33df829d2976d6de5316ec/xnu/osfmk/kern/debug.c#L1874.
        KernelCache slide and Kernel slide differ, and the "vm_kernel_slide" symbol value will be slightly incorrect, on a MH_FILESET.
        """
        # Convenient module to ease symbol values access
        module = context.module(
            symbol_table, layer_name, aslr_shift - cls._KERNEL_MIN_ADDRESS
        )

        # https://github.com/apple-open-source/macos/blob/14.3/xnu/pexpert/gen/kcformat.c#L41
        primary_kc_index = module.get_enumeration("kc_index").choices[
            "primary_kc_index"
        ]
        collection_mach_headers = module.object_from_symbol("collection_mach_headers")
        kernel_cache_header_ptr = collection_mach_headers[primary_kc_index]

        # Kernel __TEXT section start
        stext = module.object_from_symbol("stext")

        """
        References :
         - https://github.com/apple-open-source/macos/blob/14.3/xnu/pexpert/gen/kcformat.c#L190
         - https://github.com/apple-open-source/macos/blob/14.3/xnu/osfmk/kern/debug.c#L1870
        """
        return cls.virtual_to_physical_address(
            stext - kernel_cache_header_ptr + vm_kernel_slide
        )

    @classmethod
    def detect_mh_fileset_kernel_cache(
        cls,
        context: interfaces.context.ContextInterface,
        symbol_table: str,
        layer_name: str,
        aslr_shift: int,
    ) -> bool:
        """
        *MH_FILESET is a new Mach-O feature in recent macOS and iOS binaries where kernel extensions and libraries are collected into a single large file.*
         - source : binary.ninja
        """
        # Convenient module to ease symbol values access
        module = context.module(
            symbol_table, layer_name, aslr_shift - cls._KERNEL_MIN_ADDRESS
        )

        # https://github.com/apple-open-source/macos/blob/14.3/xnu/pexpert/gen/kcformat.c#L41
        primary_kc_index = module.get_enumeration("kc_index").choices[
            "primary_kc_index"
        ]
        collection_mach_headers = module.object_from_symbol("collection_mach_headers")
        kernel_cache_header_ptr = collection_mach_headers[primary_kc_index]

        # https://github.com/apple-open-source/macos/blob/14.3/xnu/EXTERNAL_HEADERS/mach-o/loader.h#L72
        mach_header_64 = module.object(
            "mach_header_64", kernel_cache_header_ptr, absolute=True
        )

        # https://github.com/apple-open-source/macos/blob/14.3/kext_tools/kclist_main.c#L63
        if mach_header_64.filetype == 0xC:
            vollog.log(
                constants.LOGLEVEL_VVVV,
                f"Detected an MH_FILESET KernelCache.",
            )
            return True
        else:
            return False

    @classmethod
    def virtual_to_physical_address(cls, addr: int) -> int:
        """Converts a virtual mac address to a physical one (does not account
        of ASLR)"""
        if addr > cls._KERNEL_MIN_ADDRESS:
            addr = addr - cls._KERNEL_MIN_ADDRESS
        else:
            addr = addr - 0xFF8000000000

        return addr

    @classmethod
    def _lowglo_scan_generator(
        cls,
        context: interfaces.context.ContextInterface,
        layer_name: str,
        progress_callback: constants.ProgressCallback,
    ):
        """
        References :
         - https://github.com/apple-open-source/macos/blob/10.8/xnu/osfmk/x86_64/lowmem_vectors.c#L78
         - https://github.com/apple-open-source/macos/blob/14.3/xnu/osfmk/x86_64/lowmem_vectors.c#L79
        """
        lowglo_signature = rb"Catfish \x00\x00"
        for offset in context.layers[layer_name].scan(
            scanner=scanners.RegExScanner(lowglo_signature),
            context=context,
            progress_callback=progress_callback,
        ):
            yield offset

    @classmethod
    def _scan_generator(cls, context, layer_name, progress_callback):
        """Kept for backward compatibility."""
        darwin_signature = (
            rb"Darwin Kernel Version \d{1,3}\.\d{1,3}\.\d{1,3}: [^\x00]+\x00"
        )

        for offset in context.layers[layer_name].scan(
            scanner=scanners.RegExScanner(darwin_signature),
            context=context,
            progress_callback=progress_callback,
        ):
            banner = context.layers[layer_name].read(offset, 128)

            idx = banner.find(b"\x00")
            if idx != -1:
                banner = banner[:idx]

            yield offset, banner


class MacSymbolFinder(symbol_finder.SymbolFinder):
    """Mac symbol loader based on uname signature strings."""

    banner_config_key = "kernel_banner"
    operating_system = "mac"
    find_aslr = MacIntelStacker.find_aslr
    symbol_class = "volatility3.framework.symbols.mac.MacKernelIntermedSymbols"
    exclusion_list = ["windows", "linux"]
    mh_fileset_config_path_prefix = interfaces.configuration.path_join(
        "temporary", "MacIntelMhFilesetHelper"
    )
