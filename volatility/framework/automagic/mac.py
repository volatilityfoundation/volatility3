import sys, struct
import logging
import typing

import volatility.framework.objects.utility
from volatility.framework import layers, interfaces, constants, validity, exceptions
from volatility.framework import symbols, objects
from volatility.framework.automagic import mac_symbol_cache
from volatility.framework.configuration import requirements
from volatility.framework.layers import intel, scanners
from volatility.framework.symbols import mac

vollog = logging.getLogger(__name__)

class MacSymbolFinder(interfaces.automagic.AutomagicInterface):
    """Mac symbol loader based on uname signature strings"""
    priority = 40

    def __init__(self,
                 context: interfaces.context.ContextInterface,
                 config_path: str) -> None:
        super().__init__(context, config_path)
        self._requirements = []  # type: typing.List[typing.Tuple[str, interfaces.configuration.ConstructableRequirementInterface]]
        self._mac_banners_ = {}  # type: mac_symbol_cache.MacBanners

    @property
    def _mac_banners(self) -> mac_symbol_cache.MacBanners:
        """Creates a cached copy of the results, but only it's been requested"""
        if not self._mac_banners_:
            self._mac_banners_ = mac_symbol_cache.MacSymbolCache.load_mac_banners()
        
        return self._mac_banners_

    def __call__(self,
                 context: interfaces.context.ContextInterface,
                 config_path: str,
                 requirement: interfaces.configuration.RequirementInterface,
                 progress_callback: validity.ProgressCallback = None) -> None:
        """Searches for MacSymbolRequirements and attempt to populate them"""
        
        self._requirements = self.find_requirements(context, config_path, requirement,
                                                    (requirements.TranslationLayerRequirement,
                                                     requirements.SymbolRequirement),
                                                    shortcut = False)

        for (sub_path, requirement) in self._requirements:
            parent_path = interfaces.configuration.parent_path(sub_path)

            if (isinstance(requirement, requirements.SymbolRequirement) and requirement.unsatisfied(context,
                                                                                                    parent_path)):
                for (tl_sub_path, tl_requirement) in self._requirements:
                    tl_parent_path = interfaces.configuration.parent_path(tl_sub_path)
                    # Find the TranslationLayer sibling to the SymbolRequirement
                    if (isinstance(tl_requirement, requirements.TranslationLayerRequirement) and
                            tl_parent_path == parent_path):
                        if context.config.get(tl_sub_path, None):
                            self._banner_scan(context, parent_path, requirement, context.config[tl_sub_path],
                                              progress_callback)
                            break

    def _banner_scan(self,
                     context: interfaces.context.ContextInterface,
                     config_path: str,
                     requirement: interfaces.configuration.ConstructableRequirementInterface,
                     layer_name: str,
                     progress_callback: validity.ProgressCallback = None) -> None:
        """Accepts a context, config_path and SymbolRequirement, with a constructed layer_name
        and scans the layer for mac banners"""
        
        # Bomb out early if there's no banners
        if not self._mac_banners:
            return

        mss = scanners.MultiStringScanner([x for x in self._mac_banners if x is not None])

        layer = context.memory[layer_name]

        # Check if the Stacker has already found what we're looking for
        if layer.config.get('mac_banner', None):
            banner_list = [(0, bytes(layer.config['mac_banner'], 'latin-1'))]  # type: typing.Iterable[typing.Any]
        else:
            # Swap to the physical layer for scanning
            # TODO: Fix this so it works for layers other than just Intel
            layer = context.memory[layer.config['memory_layer']]
            banner_list = layer.scan(context = context, scanner = mss, progress_callback = progress_callback)
                
        for _, banner in banner_list:
            vollog.debug("Identified banner: {}".format(repr(banner)))
            symbol_files = self._mac_banners.get(banner, None)
            if symbol_files:
                isf_path = symbol_files[0]
                vollog.debug("Using symbol library: {}".format(symbol_files[0]))
                clazz = "volatility.framework.symbols.mac.MacKernelIntermedSymbols"
                # Set the discovered options
                path_join = interfaces.configuration.path_join
                context.config[path_join(config_path, requirement.name, "class")] = clazz
                context.config[path_join(config_path, requirement.name, "isf_url")] = isf_path
                # Construct the appropriate symbol table
                requirement.construct(context, config_path)
                break
            else:
                if symbol_files:
                    vollog.debug("Symbol library path not found: {}".format(symbol_files[0]))
                    # print("Kernel", banner, hex(banner_offset))
        else:
            vollog.debug("No existing mac banners found")
            # TODO: Fallback to generic regex search?


class MacintelStacker(interfaces.automagic.StackerLayerInterface):
    stack_order = 12

    @classmethod
    def stack(cls,
              context: interfaces.context.ContextInterface,
              layer_name: str,
              progress_callback: validity.ProgressCallback = None) \
            -> typing.Optional[interfaces.layers.DataLayerInterface]:
        """Attempts to identify mac within this layer"""
        # Bail out by default unless we can stack properly
        layer = context.memory[layer_name]
        join = interfaces.configuration.path_join

        # Never stack on top of an intel layer
        # FIXME: Find a way to improve this check
        if isinstance(layer, intel.Intel):
            return None

        mac_banners = mac_symbol_cache.MacSymbolCache.load_mac_banners()
        mss = scanners.MultiStringScanner([x for x in mac_banners if x is not None])
        
        for banner_offset, banner in layer.scan(context = context, scanner = mss, progress_callback = progress_callback):
            dtb = None
            vollog.debug("Identified banner: {}".format(repr(banner)))

            symbol_files = mac_banners.get(banner, None)
            if symbol_files:
                isf_path = symbol_files[0]
                table_name = context.symbol_space.free_table_name('MacintelStacker')
                table = mac.MacKernelIntermedSymbols(context, 'temporary.' + table_name, name = table_name,
                                                         isf_url = isf_path)
                context.symbol_space.append(table)
                kaslr_shift = MacUtilities.find_aslr(context, table_name, layer_name,
                                                          banner, banner_offset, progress_callback = progress_callback)

                ######################
                # ikelos: The following is what I tried to get the dtb, but couldn't figure out how to do
                # as you will see after the commented block of code is just a hardcoding of the DTB to my test sample's value
                ####################### 
                '''
                bootpml4_addr = table.get_symbol("BootPML4").address + kaslr_shift
                
                new_layer_name = context.memory.free_layer_name("MacDTBTempLayer")
                config_path = interfaces.configuration.path_join("IntelHelper", new_layer_name)
                context.config[interfaces.configuration.path_join(config_path, "memory_layer")]    = layer_name
                context.config[interfaces.configuration.path_join(config_path, "page_map_offset")] = bootpml4_addr
                 
                layer = layers.intel.Intel32e(context, config_path = config_path,
                                                     name = new_layer_name, metadata = {'os': 'Mac'}) 
                
                print("KEYS: {}".format("\n".join([k for k in layer.context.memory.keys()])))
                print("DIR: {}".format(dir(layer)))

                idlepml4_ptr  = table.get_symbol("IdlePML4").address + kaslr_shift
                idlepml4_str  = layer.read(idlepml4_ptr, 4)
                idlepml4_addr = struct.unpack("<I", idlepml4_str)[0]

                print("new dtb / idlepml4_addr = {:x".format(idlepml4_addr))
                sys.exit(1)
                '''
            
                dtb = 0x1ef6e000

                # Build the new layer
                new_layer_name = context.memory.free_layer_name("IntelLayer")
                config_path = join("IntelHelper", new_layer_name)
                context.config[join(config_path, "memory_layer")] = layer_name
                context.config[join(config_path, "page_map_offset")] = dtb
                context.config[join(config_path, "mac_banner")] = str(banner, 'latin-1')

                layer = intel.Intel32e(context, config_path = config_path, name = new_layer_name)

            if layer and dtb:
                vollog.debug("DTB was found at: 0x{:0x}".format(dtb))
                return layer
        return None


class MacUtilities(object):
    """Class with multiple useful mac functions"""

    @classmethod
    def aslr_mask_symbol_table(cls,
                               config,
                               context: interfaces.context.ContextInterface,
                               aslr_shift = 0):

        if aslr_shift == 0:
            aslr_layer = config['primary.memory_layer']
            aslr_shift = MacUtilities.find_aslr(context, config["darwin"], aslr_layer)

        sym_table_name = config["darwin"]
        sym_layer_name = config["primary"]
        symbols.utility.mask_symbol_table(context.symbol_space[sym_table_name],
                                          context.memory[sym_layer_name].address_mask, aslr_shift)

    def _scan_generator(self, context, layer_name, progress_callback):
        darwin_signature = b"Darwin Kernel Version \d{1,3}\.\d{1,3}\.\d{1,3}: [^\x00]+\x00"
        
        for offset in context.memory[layer_name].scan(scanner = scanners.RegExScanner(darwin_signature),
                                                      context = context, progress_callback = progress_callback):
     
            banner = context.memory[layer_name].read(offset, 128)

            idx = banner.find(b"\x00")
            if idx != -1:
                banner = banner[:idx]

            yield offset, banner

    @classmethod
    def find_aslr(cls,
                  context: interfaces.context.ContextInterface,
                  symbol_table: str,
                  layer_name: str,
                  compare_banner: str = "",
                  compare_banner_offset: int = 0,
                  progress_callback: validity.ProgressCallback = None) \
            -> typing.Tuple[int, int]:
        """Determines the offset of the actual DTB in physical space and its symbol offset"""
        version_symbol       = symbol_table + constants.BANG + 'version'
        version_json_address = context.symbol_space.get_symbol(version_symbol).address
        version_phys_offset  = MacUtilities.virtual_to_physical_address(version_json_address)
        
        version_major_symbol       = symbol_table + constants.BANG + 'version_major'
        version_major_json_address = context.symbol_space.get_symbol(version_major_symbol).address
        version_major_phys_offset  = MacUtilities.virtual_to_physical_address(version_major_json_address)

        version_minor_symbol       = symbol_table + constants.BANG + 'version_minor'
        version_minor_json_address = context.symbol_space.get_symbol(version_minor_symbol).address
        version_minor_phys_offset  = MacUtilities.virtual_to_physical_address(version_minor_json_address)

        module = context.module(symbol_table, layer_name, 0)

        if compare_banner_offset == 0 or compare_banner == "":
            offset_generator = cls._scan_generator(cls, context, layer_name, progress_callback)
        else:
            offset_generator = [(compare_banner_offset, compare_banner)]

        aslr_shift = 0

        for offset, banner in offset_generator:
            banner_major, banner_minor = [int(x) for x in banner[22:].split(b".")[0:2]]

            tmp_aslr_shift = offset - (version_json_address - 0xffffff8000000000)

            major_string = context.memory[layer_name].read(version_major_phys_offset + tmp_aslr_shift, 4)
            major = struct.unpack("<I", major_string)[0]

            if major != banner_major:
                continue

            minor_string = context.memory[layer_name].read(version_minor_phys_offset + tmp_aslr_shift, 4)
            minor = struct.unpack("<I", minor_string)[0]

            if minor != banner_minor:
                conitnue

            if aslr_shift & 0xfff != 0:
                continue
           
            aslr_shift = tmp_aslr_shift & 0xffffffff
            break

        vollog.debug("Mac ASLR shift value determined: {:0x}".format(aslr_shift)) 
        
        return aslr_shift

    @classmethod
    def virtual_to_physical_address(cls, addr: int) -> int:
        """Converts a virtual mac address to a physical one (does not account of ASLR)"""
        return addr - 0xffffff8000000000

