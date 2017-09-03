import logging

from volatility.framework import interfaces, constants
from volatility.framework.automagic import linux_symbol_cache
from volatility.framework.layers import intel, scanners

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
                        # TODO: Find the physical layer properly, not just for Intel
                        physical_path = interfaces.configuration.path_join(tl_sub_path, "memory_layer")
                        # Ensure the stackers succeeded
                        if context.config.get(physical_path, None):
                            self._banner_scan(context, path, requirement, context.config[physical_path],
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

        for offset, banner in layer.scan(context = context, scanner = mss, progress_callback = progress_callback):
            vollog.debug("Identified banner: {}".format(repr(banner)))
            symbol_files = self._linux_banners[banner]
            if symbol_files:
                isf_path = symbol_files[0]
                vollog.debug("Using symbol library: {}".format(symbol_files[0]))
                clazz = "volatility.framework.symbols.linux.LinuxKernelIntermedSymbols"
                # Set the discovered options
                path_join = interfaces.configuration.path_join
                context.config[path_join(config_path, requirement.name, "class")] = clazz
                context.config[path_join(config_path, requirement.name, "isf_filepath")] = isf_path
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
    linux_signature = b"SYMBOL\(swapper_pg_dir\)=.*"
    stack_order = 12

    @classmethod
    def stack(cls, context, layer_name, progress_callback = None):
        """Attempts to identify linux within this layer"""
        layer = context.memory[layer_name]

        # Bail out if we're not a physical layer
        # TODO: We need a better way of doing this
        if isinstance(layer, intel.Intel):
            return None

        virtual_dtb = cls.determine_virtual_dtb(context, layer_name, progress_callback)
        if virtual_dtb is not None:
            new_layer_name = context.memory.free_layer_name("IntelLayer")
            config_path = interfaces.configuration.path_join("IntelHelper", new_layer_name)
            context.config[interfaces.configuration.path_join(config_path, "memory_layer")] = layer_name

            if virtual_dtb > 0xffffffff80000000:
                layer_class = intel.Intel32e
            else:
                layer_class = intel.Intel
            dtb = LinuxUtilities.virtual_to_physical_address(virtual_dtb)
            context.config[interfaces.configuration.path_join(config_path, "page_map_offset")] = virtual_dtb

            layer = layer_class(context, config_path = config_path, name = new_layer_name)
        if layer:
            vollog.debug("DTB was found at: 0x{:0x}".format(virtual_dtb))
        return layer

    @classmethod
    def determine_virtual_dtb(cls, context, layer_name, progress_callback = None):
        layer = context.memory[layer_name]

        swapper_pg_dirs = []
        for offset in layer.scan(scanner = scanners.RegExScanner(cls.linux_signature), context = context,
                                 progress_callback = progress_callback):
            swapper_pg_dir_text = context.memory[layer_name].read(offset, len(cls.linux_signature) + 20)
            swapper_pg_dir = int(swapper_pg_dir_text[
                                 swapper_pg_dir_text.index(b"=") + 1:swapper_pg_dir_text.index(b"\n")], 16)
            swapper_pg_dirs.append(swapper_pg_dir)

        dtb = 0
        if swapper_pg_dirs:
            dtb = list(reversed(sorted(set(swapper_pg_dirs), key = lambda x: swapper_pg_dirs.count(x))))[0]

            return dtb
        return None


class LinuxUtilities(object):
    """Class with multiple useful linux functions"""

    @classmethod
    def find_aslr(cls, context, symbol_table, layer_name, progress_callback = None):
        """Determines the virtual ASLR value"""
        path_join = interfaces.configuration.path_join
        # Find the symbol table's version of the DTB
        swapper_pg_dir_name = symbol_table + constants.BANG + 'init_level4_pgt'
        table_dtb = context.symbol_space.get_symbol(swapper_pg_dir_name).address

        # Find the image's version of the DTB
        image_dtb = LintelStacker.determine_virtual_dtb(context, layer_name, progress_callback)

        # Subtract the actual from the supposed to get the shift
        vaslr_shift = image_dtb - table_dtb
        return vaslr_shift

    @classmethod
    def find_kaslr(cls, context, symbol_table, layer_name, progress_callback = None):
        """Determines the offset of the actual DTB in physical space and its symbol offset"""
        init_task_symbol = symbol_table + constants.BANG + 'init_task'
        table_dtb = context.symbol_space.get_symbol(init_task_symbol).address
        swapper_signature = b"swapper/0\x00\x00\x00\x00\x00\x00"
        module = context.module(symbol_table, layer_name, 0)

        for offset in context.memory[layer_name].scan(scanner = scanners.RegExScanner(swapper_signature),
                                                      context = context, progress_callback = progress_callback):
            task_symbol = module.get_type('task_struct')
            image_dtb = offset - task_symbol.members['comm'][0]
            init_task = module.object(type_name = 'task_struct', offset = image_dtb)
            if init_task.pid != 0:
                continue
            if init_task.thread_info.cast('unsigned int') != 0:
                continue
            # This we get for free
            aslr_shift = init_task.files.cast('long long unsigned int') - module.get_symbol('init_files').address
            kaslr_shift = image_dtb - cls.virtual_to_physical_address(table_dtb)
            return kaslr_shift
        return None

    @classmethod
    def virtual_to_physical_address(cls, addr):
        """Converts a virtual linux address to a physical one (does not account of ASLR)"""
        if addr > 0xffffffff80000000:
            return addr - 0xffffffff80000000
        return addr - 0xc0000000
