import logging

from volatility.framework import interfaces, constants
from volatility.framework.automagic import linux_symbol_cache
from volatility.framework.layers import intel, scanners
from volatility.framework.symbols import linux

vollog = logging.getLogger(__name__)


class LinuxSymbolFinder(interfaces.automagic.AutomagicInterface):
    """Linux symbol loader based on uname signature strings"""
    priority = 40

    def __init__(self, context, config_path):
        super().__init__(context, config_path)
        self._requirements = None
        self._linux_banners = linux_symbol_cache.LinuxSymbolCache.load_linux_banners()

    def __call__(self, context, config_path, requirement, progress_callback = None):
        """Searches for LinuxSymbolRequirements and attempt to populate them"""
        self._requirements = self.find_requirements(context, config_path, requirement,
                                                    (interfaces.configuration.TranslationLayerRequirement,
                                                     interfaces.configuration.SymbolRequirement),
                                                    shortcut = False)

        for (path, sub_path, requirement) in self._requirements:
            if (isinstance(requirement, interfaces.configuration.SymbolRequirement) and
                    requirement.unsatisfied(context, path)):
                for (tl_path, tl_sub_path, tl_requirement) in self._requirements:
                    # Find the TranslationLayer sibling to the SymbolRequirement
                    if (isinstance(tl_requirement, interfaces.configuration.TranslationLayerRequirement) and
                                tl_path == path):
                        self._banner_scan(context, path, requirement, context.config[tl_sub_path],
                                          progress_callback)
                        break

    def _banner_scan(self, context, config_path, requirement, layer_name, progress_callback = None):
        """Accepts a context, config_path and SymbolRequirement, with a constructed layer_name
        and scans the layer for linux banners"""

        # Bomb out early if there's no banners
        if not self._linux_banners:
            return

        mss = scanners.MultiStringScanner([x for x in self._linux_banners if x is not None])

        layer = context.memory[layer_name]

        # Check if the Stacker has already found what we're looking for
        if layer.config.get('linux_banner', None):
            banner_list = [(0, bytes(layer.config['linux_banner'], 'latin-1'))]
        else:
            # Swap to the physical layer for scanning
            # TODO: Fix this so it works for layers other than just Intel
            layer = context.memory[layer.config['memory_layer']]
            banner_list = layer.scan(context = context, scanner = mss, progress_callback = progress_callback)

        for _, banner in banner_list:
            vollog.debug("Identified banner: {}".format(repr(banner)))
            symbol_files = self._linux_banners.get(banner, None)
            if symbol_files:
                isf_path = symbol_files[0]
                vollog.debug("Using symbol library: {}".format(symbol_files[0]))
                clazz = "volatility.framework.symbols.linux.LinuxKernelIntermedSymbols"
                # Set the discovered options
                path_join = interfaces.configuration.path_join
                context.config[path_join(config_path, requirement.name, "class")] = clazz
                context.config[path_join(config_path, requirement.name, "isf_url")] = isf_path
                # Construct the appropriate symbol table
                requirement.construct(context, config_path)
                break
            else:
                vollog.debug("Symbol library path not found: {}".format(symbol_files[0]))
                # print("Kernel", banner, hex(banner_offset))
        else:
            vollog.debug("No existing linux banners found")
            # TODO: Fallback to generic regex search?


class LintelStacker(interfaces.automagic.StackerLayerInterface):
    stack_order = 12

    @classmethod
    def stack(cls, context, layer_name, progress_callback = None):
        """Attempts to identify linux within this layer"""
        layer = context.memory[layer_name]
        join = interfaces.configuration.path_join

        # Bail out if we're not a physical layer
        # TODO: We need a better way of doing this
        if isinstance(layer, intel.Intel):
            return None

        dtb = None

        linux_banners = linux_symbol_cache.LinuxSymbolCache.load_linux_banners()
        mss = scanners.MultiStringScanner([x for x in linux_banners if x is not None])
        for _, banner in layer.scan(context = context, scanner = mss, progress_callback = progress_callback):
            vollog.debug("Identified banner: {}".format(repr(banner)))
            symbol_files = linux_banners.get(banner, None)
            if symbol_files:
                isf_path = symbol_files[0]
                table_name = context.symbol_space.free_table_name('LintelStacker')
                table = linux.LinuxKernelIntermedSymbols(context, 'temporary.' + table_name, name = table_name,
                                                         isf_url = isf_path)
                context.symbol_space.append(table)
                kaslr_shift, _ = LinuxUtilities.find_aslr(context, table_name, layer_name,
                                                          progress_callback = progress_callback)

                if ('init_level4_pgt' in table.symbols):
                    layer_class = intel.Intel32e
                    dtb_symbol_name = 'init_level4_pgt'
                else:
                    layer_class = intel.Intel
                    dtb_symbol_name = 'swapper_pg_dir'

                dtb = LinuxUtilities.virtual_to_physical_address(table.get_symbol(dtb_symbol_name).address +
                                                                 kaslr_shift)

                # Build the new layer
                new_layer_name = context.memory.free_layer_name("IntelLayer")
                config_path = join("IntelHelper", new_layer_name)
                context.config[join(config_path, "memory_layer")] = layer_name
                context.config[join(config_path, "page_map_offset")] = dtb
                context.config[join(config_path, "linux_banner")] = str(banner, 'latin-1')

                layer = layer_class(context, config_path = config_path, name = new_layer_name)

        if layer:
            vollog.debug("DTB was found at: 0x{:0x}".format(dtb))
        return layer


class LinuxUtilities(object):
    """Class with multiple useful linux functions"""

    @classmethod
    def find_aslr(cls, context, symbol_table, layer_name, progress_callback = None):
        """Determines the offset of the actual DTB in physical space and its symbol offset"""
        init_task_symbol = symbol_table + constants.BANG + 'init_task'
        table_dtb = context.symbol_space.get_symbol(init_task_symbol).address
        swapper_signature = b"swapper/0\x00\x00\x00\x00\x00\x00"
        module = context.module(symbol_table, layer_name, 0)

        for offset in context.memory[layer_name].scan(scanner = scanners.RegExScanner(swapper_signature),
                                                      context = context, progress_callback = progress_callback):
            task_symbol = module.get_type('task_struct')
            image_dtb = offset - task_symbol.relative_child_offset('comm')
            init_task = module.object(type_name = 'task_struct', offset = image_dtb)
            if init_task.pid != 0:
                continue
            if hasattr(init_task, 'thread_info') and init_task.thread_info.cast('unsigned int') != 0:
                continue
            elif (hasattr(init_task, 'state') and init_task.state.cast('unsigned int') != 0):
                continue
            # This we get for free
            aslr_shift = init_task.files.cast('long long unsigned int') - module.get_symbol('init_files').address
            kaslr_shift = image_dtb - cls.virtual_to_physical_address(table_dtb)

            if aslr_shift & 0xfff != 0 or kaslr_shift & 0xfff != 0:
                continue
            vollog.debug(
                "Linux ASLR shift values determined: physical {:0x} virtual {:0x}".format(kaslr_shift, aslr_shift))
            return kaslr_shift, aslr_shift
        return None, None

    @classmethod
    def virtual_to_physical_address(cls, addr):
        """Converts a virtual linux address to a physical one (does not account of ASLR)"""
        if addr > 0xffffffff80000000:
            return addr - 0xffffffff80000000
        return addr - 0xc0000000
