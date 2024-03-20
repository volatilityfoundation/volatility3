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
                config_path = join("automagic", "MacIntelHelper", new_layer_name)
                context.config[join(config_path, "memory_layer")] = layer_name
                context.config[join(config_path, "page_map_offset")] = dtb
                context.config[join(config_path, MacSymbolFinder.banner_config_key)] = (
                    str(banner, "latin-1")
                )

                new_layer = intel.Intel32e(
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

            tmp_aslr_shift = offset - cls.virtual_to_physical_address(
                version_json_address
            )

            major_string = context.layers[layer_name].read(
                version_major_phys_offset + tmp_aslr_shift, 4
            )
            major = struct.unpack("<I", major_string)[0]

            if major != banner_major:
                continue

            minor_string = context.layers[layer_name].read(
                version_minor_phys_offset + tmp_aslr_shift, 4
            )
            minor = struct.unpack("<I", minor_string)[0]

            if minor != banner_minor:
                continue

            if tmp_aslr_shift & 0xFFF != 0:
                continue

            aslr_shift = tmp_aslr_shift & 0xFFFFFFFF
            break

        vollog.log(constants.LOGLEVEL_VVVV, f"Mac find_aslr returned: {aslr_shift:0x}")

        return aslr_shift

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
