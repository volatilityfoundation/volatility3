# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

import logging
import os
import struct
from typing import Optional, Type

from volatility3.framework import constants, interfaces
from volatility3.framework.automagic import symbol_cache, symbol_finder
from volatility3.framework.configuration import requirements
from volatility3.framework.layers import intel, scanners
from volatility3.framework.symbols import freebsd

vollog = logging.getLogger(__name__)


class FreebsdIntelStacker(interfaces.automagic.StackerLayerInterface):
    stack_order = 35
    exclusion_list = ["linux", "mac", "windows"]

    @classmethod
    def stack(
        cls,
        context: interfaces.context.ContextInterface,
        layer_name: str,
        progress_callback: constants.ProgressCallback = None,
    ) -> Optional[interfaces.layers.DataLayerInterface]:
        """Attempts to identify freebsd within this layer."""
        # Version check the SQlite cache
        required = (1, 0, 0)
        if not requirements.VersionRequirement.matches_required(required, symbol_cache.SqliteCache.version):
            vollog.info(
                f"SQLiteCache version not suitable: required {required} found {symbol_cache.SqliteCache.version}")
            return None

        # Bail out by default unless we can stack properly
        layer = context.layers[layer_name]
        join = interfaces.configuration.path_join

        # Never stack on top of an intel layer
        # FIXME: Find a way to improve this check
        if isinstance(layer, intel.Intel):
            return None

        identifiers_path = os.path.join(constants.CACHE_PATH, constants.IDENTIFIERS_FILENAME)
        freebsd_banners = symbol_cache.SqliteCache(identifiers_path).get_identifier_dictionary(
            operating_system = "freebsd")
        # If we have no banners, don't bother scanning
        if not freebsd_banners:
            vollog.info(
                "No Freebsd banners found - if this is a freebsd plugin, please check your symbol files location")
            return None

        mss = scanners.MultiStringScanner([x for x in freebsd_banners if x is not None])
        for _, banner in layer.scan(context = context, scanner = mss, progress_callback = progress_callback):
            dtb = None
            vollog.debug(f"Identified banner: {repr(banner)}")

            isf_path = freebsd_banners.get(banner, None)
            if isf_path:
                table_name = context.symbol_space.free_table_name("FreebsdIntelStacker")
                table = freebsd.FreebsdKernelIntermedSymbols(
                    context,
                    "temporary." + table_name,
                    name = table_name,
                    isf_url = isf_path,
                )
                context.symbol_space.append(table)

                layer_class: Type = intel.Intel
                # Freebsd amd64
                if "KPML4phys" in table.symbols:
                    layer_class = intel.Intel32e
                    kernbase = table.get_symbol("kernbase").address
                    kpml4phys_ptr = table.get_symbol("KPML4phys").address
                    kpml4phys_str = layer.read(kpml4phys_ptr - kernbase, 8)
                    dtb = struct.unpack("<Q", kpml4phys_str)[0]
                # Freebsd i386
                elif "IdlePTD" in table.symbols:
                    layer_class = intel.Intel
                    if "tramp_idleptd" in table.symbols:
                        kernbase = 0
                    else:
                        kernbase = table.get_symbol("kernbase").address
                    idleptd_ptr = table.get_symbol("IdlePTD").address
                    idleptd_str = layer.read(idleptd_ptr - kernbase, 4)
                    dtb = struct.unpack("<I", idleptd_str)[0]
                # Freebsd i386 after merge of PAE and non-PAE pmaps into same kernel
                elif "IdlePTD_nopae" in table.symbols:
                    pae_mode_addr = table.get_symbol("pae_mode").address
                    pae_mode = layer.read(pae_mode_addr, 4)
                    if pae_mode == b'\x01\x00\x00\x00':
                        layer_class = intel.IntelPAE
                        idlepdpt_ptr = table.get_symbol("IdlePDPT").address
                        idlepdpt_str = layer.read(idlepdpt_ptr, 4)
                        dtb = struct.unpack("<I", idlepdpt_str)[0]
                    elif pae_mode == b'\x00\x00\x00\x00':
                        layer_class = intel.Intel
                        idleptd_ptr = table.get_symbol("IdlePTD_nopae").address
                        idleptd_str = layer.read(idleptd_ptr, 4)
                        dtb = struct.unpack("<I", idleptd_str)[0]
                # Freebsd i386 with PAE
                elif "IdlePDPT" in table.symbols:
                    layer_class = intel.IntelPAE
                    if "tramp_idleptd" in table.symbols:
                        kernbase = 0
                    else:
                        kernbase = table.get_symbol("kernbase").address
                    idlepdpt_ptr = table.get_symbol("IdlePDPT").address
                    idlepdpt_str = layer.read(idlepdpt_ptr - kernbase, 4)
                    dtb = struct.unpack('<I', idlepdpt_str)[0]

                # Build the new layer
                new_layer_name = context.layers.free_layer_name("IntelLayer")
                config_path = join("IntelHelper", new_layer_name)
                context.config[join(config_path, "memory_layer")] = layer_name
                context.config[join(config_path, "page_map_offset")] = dtb
                context.config[join(config_path, FreebsdSymbolFinder.banner_config_key)] = str(banner, "latin-1")

                layer = layer_class(
                    context,
                    config_path = config_path,
                    name = new_layer_name,
                    metadata = {"os": "freebsd"},
                )
                layer.config["kernel_virtual_offset"] = 0

            if layer and dtb:
                vollog.debug(f"DTB was found at: 0x{dtb:0x}")
                return layer
        vollog.debug("No suitable freebsd banner could be matched")
        return None


class FreebsdSymbolFinder(symbol_finder.SymbolFinder):
    """Freebsd symbol loader based on uname signature strings."""

    banner_config_key = "kernel_banner"
    operating_system = "freebsd"
    symbol_class = "volatility3.framework.symbols.freebsd.FreebsdKernelIntermedSymbols"
    exclusion_list = ["linux", "mac", "windows"]
