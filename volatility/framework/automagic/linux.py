import logging

from volatility.framework import interfaces
from volatility.framework.automagic import linux_symbol_cache
from volatility.framework.layers import intel, scanners

vollog = logging.getLogger(__name__)


class LinuxSymbolFinder(interfaces.automagic.AutomagicInterface):
    priority = 20

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
            if isinstance(requirement, interfaces.configuration.SymbolRequirement):
                for (tl_path, tl_sub_path, tl_requirement) in self._requirements:
                    # Find the TranslationLayer sibling to the SymbolRequirement
                    if (isinstance(tl_requirement, interfaces.configuration.TranslationLayerRequirement) and
                                tl_path == path):
                        # TODO: Find the physical layer properly, not just for Intel
                        physical_path = interfaces.configuration.path_join(tl_sub_path, "memory_layer")
                        self._banner_scan(context, path, requirement, context.config[physical_path],
                                          progress_callback)

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
            isf_path = "file://" + symbol_files[0]
            if isf_path:
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
            pass


class LintelStacker(interfaces.automagic.StackerLayerInterface):
    linux_signature = b"SYMBOL\(swapper_pg_dir\)=.*"
    stack_order = 9

    @classmethod
    def stack(cls, context, layer_name, progress_callback = None):
        """Attempts to identify linux within this layer"""
        layer = context.memory[layer_name]

        # Bail out if we're not a physical layer
        # TODO: We need a better way of doing this
        if isinstance(layer, intel.Intel):
            return None

        swapper_pg_dirs = []
        for offset in layer.scan(scanner = scanners.RegExScanner(cls.linux_signature), context = context):
            swapper_pg_dir_text = context.memory[layer_name].read(offset, len(cls.linux_signature) + 20)
            swapper_pg_dir = int(swapper_pg_dir_text[
                                 swapper_pg_dir_text.index(b"=") + 1:swapper_pg_dir_text.index(b"\n")], 16)
            swapper_pg_dirs.append(swapper_pg_dir)

        if swapper_pg_dirs:
            best_swapper_pg_dir = \
                list(reversed(sorted(set(swapper_pg_dirs), key = lambda x: swapper_pg_dirs.count(x))))[0]

            if best_swapper_pg_dir > 0xffffffff80000000:
                shift = 0xffffffff80000000
                layer_class = intel.Intel32e
            else:
                shift = 0xc0000000
                layer_class = intel.Intel
            dtb = best_swapper_pg_dir - shift

            new_layer_name = context.memory.free_layer_name("IntelLayer")
            config_path = interfaces.configuration.path_join("IntelHelper", new_layer_name)
            context.config[interfaces.configuration.path_join(config_path, "memory_layer")] = layer_name
            context.config[interfaces.configuration.path_join(config_path, "page_map_offset")] = dtb

            layer = layer_class(context, config_path = config_path, name = new_layer_name)
        if layer:
            vollog.debug("DTB was found at: 0x{:0x}".format(dtb))
        return layer
