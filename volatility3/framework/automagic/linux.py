# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

import logging
from typing import Optional, Tuple

from volatility3.framework import constants, interfaces
from volatility3.framework.automagic import symbol_cache, symbol_finder
from volatility3.framework.configuration import requirements
from volatility3.framework.layers import intel, scanners
from volatility3.framework.symbols import linux

vollog = logging.getLogger(__name__)


class LinuxIntelStacker(interfaces.automagic.StackerLayerInterface):
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
        # Bail out by default unless we can stack properly
        layer = context.layers[layer_name]
        join = interfaces.configuration.path_join

        # Never stack on top of an intel layer
        # FIXME: Find a way to improve this check
        if isinstance(layer, intel.Intel):
            return None

        linux_banners = symbol_cache.load_cache_manager().get_identifier_dictionary(
            operating_system="linux"
        )
        # If we have no banners, don't bother scanning
        if not linux_banners:
            vollog.info(
                "No Linux banners found - if this is a linux plugin, please check your symbol files location"
            )
            return None

        mss = scanners.MultiStringScanner([x for x in linux_banners if x is not None])
        for _, banner in layer.scan(
            context=context, scanner=mss, progress_callback=progress_callback
        ):
            dtb = None
            vollog.debug(f"Identified banner: {repr(banner)}")

            isf_path = linux_banners.get(banner, None)
            if isf_path:
                table_name = context.symbol_space.free_table_name("LintelStacker")
                table = linux.LinuxKernelIntermedSymbols(
                    context,
                    "temporary." + table_name,
                    name=table_name,
                    isf_url=isf_path,
                )
                context.symbol_space.append(table)

                kaslr_shift, aslr_shift = cls.find_aslr(
                    context,
                    table_name,
                    layer_name,
                    progress_callback=progress_callback,
                )

                if "init_top_pgt" in table.symbols:
                    layer_class = intel.LinuxIntel32e
                    dtb_symbol_name = "init_top_pgt"
                elif "init_level4_pgt" in table.symbols:
                    layer_class = intel.LinuxIntel32e
                    dtb_symbol_name = "init_level4_pgt"
                elif "pkmap_count" in table.symbols and table.get_symbol(
                    "pkmap_count"
                ).type.count in (512, 2048):
                    layer_class = intel.LinuxIntelPAE
                    dtb_symbol_name = "swapper_pg_dir"
                else:
                    layer_class = intel.LinuxIntel
                    dtb_symbol_name = "swapper_pg_dir"

                dtb = cls.virtual_to_physical_address(
                    table.get_symbol(dtb_symbol_name).address + kaslr_shift
                )

                # Build the new layer
                new_layer_name = context.layers.free_layer_name("IntelLayer")
                config_path = join("IntelHelper", new_layer_name)
                context.config[join(config_path, "memory_layer")] = layer_name
                context.config[join(config_path, "page_map_offset")] = dtb
                context.config[
                    join(config_path, LinuxSymbolFinder.banner_config_key)
                ] = str(banner, "latin-1")

                layer = layer_class(
                    context,
                    config_path=config_path,
                    name=new_layer_name,
                    metadata={"os": "Linux"},
                )
                layer.config["kernel_virtual_offset"] = aslr_shift

            if layer and dtb:
                vollog.debug(f"DTB was found at: 0x{dtb:0x}")
                return layer
        vollog.debug("No suitable linux banner could be matched")
        return None

    @classmethod
    def find_aslr(
        cls,
        context: interfaces.context.ContextInterface,
        symbol_table: str,
        layer_name: str,
        progress_callback: constants.ProgressCallback = None,
    ) -> Tuple[int, int]:
        """Determines the offset of the actual DTB in physical space and its
        symbol offset.

        Args:
            context: The context to retrieve required elements (layers, symbol tables) from
            symbol_table: The name of the kernel module on which to operate
            layer_name: The layer within the context in which the module exists
            progress_callback: A function that takes a percentage (and an optional description) that will be called periodically

        Returns:
            kaslr_shirt and aslr_shift
        """
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
            elif init_task.active_mm.cast("long unsigned int") == module.get_symbol(
                "init_mm"
            ).address and init_task.tasks.next.cast(
                "long unsigned int"
            ) == init_task.tasks.prev.cast(
                "long unsigned int"
            ):
                # The idle task steals `mm` from previously running task, i.e.,
                # `init_mm` is only used as long as no CPU has ever been idle.
                # This catches cases where we found a fragment of the
                # unrelocated ELF file instead of the running kernel.
                continue

            # This we get for free
            aslr_shift = (
                int.from_bytes(
                    init_task.files.cast("bytes", length=init_task.files.vol.size),
                    byteorder=init_task.files.vol.data_format.byteorder,
                )
                - module.get_symbol("init_files").address
            )
            kaslr_shift = init_task_address - cls.virtual_to_physical_address(
                init_task_json_address
            )
            if address_mask:
                aslr_shift = aslr_shift & address_mask

            if aslr_shift & 0xFFF != 0 or kaslr_shift & 0xFFF != 0:
                continue
            vollog.debug(
                f"Linux ASLR shift values determined: physical {kaslr_shift:0x} virtual {aslr_shift:0x}"
            )
            return kaslr_shift, aslr_shift

        # We don't throw an exception, because we may legitimately not have an ASLR shift, but we report it
        vollog.debug("Scanners could not determine any ASLR shifts, using 0 for both")
        return 0, 0

    @staticmethod
    def virtual_to_physical_address(addr: int) -> int:
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
    exclusion_list = ["mac", "windows"]

    @classmethod
    def find_aslr(cls, *args):
        return LinuxIntelStacker.find_aslr(*args)[1]


class LinuxIntelVMCOREINFOStacker(interfaces.automagic.StackerLayerInterface):
    stack_order = 34
    exclusion_list = ["mac", "windows"]

    @staticmethod
    def _check_versions() -> bool:
        """Verify the versions of the required modules"""
        # Check VMCOREINFO API version
        vmcoreinfo_version_required = (1, 0, 0)
        if not requirements.VersionRequirement.matches_required(
            vmcoreinfo_version_required, linux.VMCoreInfo.version
        ):
            vollog.info(
                "VMCOREINFO version not suitable: required %s found %s",
                vmcoreinfo_version_required,
                linux.VMCoreInfo.version,
            )
            return False

        return True

    @classmethod
    def stack(
        cls,
        context: interfaces.context.ContextInterface,
        layer_name: str,
        progress_callback: constants.ProgressCallback = None,
    ) -> Optional[interfaces.layers.DataLayerInterface]:
        """Attempts to identify linux within this layer."""

        # Verify the versions of the required modules
        if not cls._check_versions():
            return None

        # Bail out by default unless we can stack properly
        layer = context.layers[layer_name]

        # Never stack on top of an intel layer
        # FIXME: Find a way to improve this check
        if isinstance(layer, intel.Intel):
            return None

        linux_banners = symbol_cache.load_cache_manager().get_identifier_dictionary(
            operating_system="linux"
        )
        if not linux_banners:
            # If we have no banners, don't bother scanning
            vollog.info(
                "No Linux banners found - if this is a linux plugin, please check your "
                "symbol files location"
            )
            return None

        vmcoreinfo_elf_notes_iter = linux.VMCoreInfo.search_vmcoreinfo_elf_note(
            context=context,
            layer_name=layer_name,
            progress_callback=progress_callback,
        )

        # Iterate through each VMCOREINFO ELF note found, using the first one that is valid.
        for _vmcoreinfo_offset, vmcoreinfo in vmcoreinfo_elf_notes_iter:
            shifts = cls._vmcoreinfo_find_aslr(vmcoreinfo)
            if not shifts:
                # Let's try the next VMCOREINFO, in case this one isn't correct.
                continue

            kaslr_shift, aslr_shift = shifts

            dtb = cls._vmcoreinfo_get_dtb(vmcoreinfo, aslr_shift, kaslr_shift)
            if dtb is None:
                # Discard this VMCOREINFO immediately
                continue

            is_32bit, is_pae = cls._vmcoreinfo_is_32bit(vmcoreinfo)
            if is_32bit:
                layer_class = intel.IntelPAE if is_pae else intel.Intel
            else:
                layer_class = intel.Intel32e

            uts_release = vmcoreinfo["OSRELEASE"]

            # See how linux_banner constant is built in the linux kernel
            linux_version_prefix = f"Linux version {uts_release} (".encode()
            valid_banners = [
                x for x in linux_banners if x and x.startswith(linux_version_prefix)
            ]
            if not valid_banners:
                # There's no banner matching this VMCOREINFO, keep trying with the next one
                continue
            elif len(valid_banners) == 1:
                # Usually, we narrow down the Linux banner list to a single element.
                # Using BytesScanner here is slightly faster than MultiStringScanner.
                scanner = scanners.BytesScanner(valid_banners[0])
            else:
                scanner = scanners.MultiStringScanner(valid_banners)

            join = interfaces.configuration.path_join
            for match in layer.scan(
                context=context, scanner=scanner, progress_callback=progress_callback
            ):
                # Unfortunately, the scanners do not maintain a consistent interface
                banner = match[1] if isinstance(match, Tuple) else valid_banners[0]

                isf_path = linux_banners.get(banner, None)
                if not isf_path:
                    vollog.warning(
                        "Identified banner %r, but no matching ISF is available.",
                        banner,
                    )
                    continue

                vollog.debug("Identified banner: %r", banner)
                table_name = context.symbol_space.free_table_name("LintelStacker")
                table = linux.LinuxKernelIntermedSymbols(
                    context,
                    f"temporary.{table_name}",
                    name=table_name,
                    isf_url=isf_path,
                )
                context.symbol_space.append(table)

                # Build the new layer
                new_layer_name = context.layers.free_layer_name("primary")
                config_path = join("vmcoreinfo", new_layer_name)
                kernel_banner = LinuxSymbolFinder.banner_config_key
                banner_str = banner.decode(encoding="latin-1")
                context.config[join(config_path, kernel_banner)] = banner_str
                context.config[join(config_path, "memory_layer")] = layer_name
                context.config[join(config_path, "page_map_offset")] = dtb
                context.config[join(config_path, "kernel_virtual_offset")] = aslr_shift
                layer = layer_class(
                    context,
                    config_path=config_path,
                    name=new_layer_name,
                    metadata={"os": "Linux"},
                )

                if layer:
                    vollog.debug(
                        "Values found in VMCOREINFO: KASLR=0x%x, ASLR=0x%x, DTB=0x%x",
                        kaslr_shift,
                        aslr_shift,
                        dtb,
                    )

                    return layer

        vollog.debug("No suitable linux banner could be matched")
        return None

    @staticmethod
    def _vmcoreinfo_find_aslr(vmcoreinfo) -> Tuple[int, int]:
        phys_base = vmcoreinfo.get("NUMBER(phys_base)")
        if phys_base is None:
            # In kernel < 4.10, there may be a SYMBOL(phys_base), but as noted in the
            # c401721ecd1dcb0a428aa5d6832ee05ffbdbffbbe commit comment, this value
            # isn't useful for calculating the physical address.
            # There's nothing we can do here, so let's try with the next VMCOREINFO or
            # the next Stacker.
            return None

        # kernels 3.14 (b6085a865762236bb84934161273cdac6dd11c2d) KERNELOFFSET was added
        kerneloffset = vmcoreinfo.get("KERNELOFFSET")
        if kerneloffset is None:
            # kernels < 3.14 if KERNELOFFSET is missing, KASLR might not be implemented.
            # Oddly, NUMBER(phys_base) is present without it. To be safe, proceed only
            # if both are present.
            return None

        aslr_shift = kerneloffset
        kaslr_shift = phys_base + aslr_shift

        return kaslr_shift, aslr_shift

    @staticmethod
    def _vmcoreinfo_get_dtb(vmcoreinfo, aslr_shift, kaslr_shift) -> int:
        """Returns the page global directory physical address (a.k.a DTB or PGD)"""
        # In x86-64, since kernels 2.5.22 swapper_pg_dir is a macro to the respective pgd.
        # First, in e3ebadd95cb621e2c7436f3d3646447ac9d5c16d to init_level4_pgt, and later
        # in kernels 4.13 in 65ade2f872b474fa8a04c2d397783350326634e6) to init_top_pgt.
        # In x86-32, the pgd is swapper_pg_dir. So, in any case, for VMCOREINFO
        # SYMBOL(swapper_pg_dir) will always have the right value.
        dtb_vaddr = vmcoreinfo.get("SYMBOL(swapper_pg_dir)")
        if dtb_vaddr is None:
            # Abort, it should be present
            return None

        dtb_paddr = (
            LinuxIntelStacker.virtual_to_physical_address(dtb_vaddr)
            - aslr_shift
            + kaslr_shift
        )

        return dtb_paddr

    @staticmethod
    def _vmcoreinfo_is_32bit(vmcoreinfo) -> Tuple[bool, bool]:
        """Returns a tuple of booleans with is_32bit and is_pae values"""
        is_pae = vmcoreinfo.get("CONFIG_X86_PAE", "n") == "y"
        if is_pae:
            is_32bit = True
        else:
            # Check the swapper_pg_dir virtual address size
            dtb_vaddr = vmcoreinfo["SYMBOL(swapper_pg_dir)"]
            is_32bit = dtb_vaddr <= 2**32

        return is_32bit, is_pae
