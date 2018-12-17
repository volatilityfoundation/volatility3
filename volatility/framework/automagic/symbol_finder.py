import logging
from typing import Any, Iterable, List, Tuple, Dict, Type, Optional

from volatility.framework import interfaces, validity
from volatility.framework.automagic import symbol_cache
from volatility.framework.configuration import requirements
from volatility.framework.layers import scanners

vollog = logging.getLogger(__name__)


class SymbolFinder(interfaces.automagic.AutomagicInterface):
    """Symbol loader based on signature strings"""
    priority = 40

    banner_config_key: str = "banner"
    banner_cache: Optional[Type[symbol_cache.SymbolBannerCache]] = None
    symbol_class: Optional[str] = None

    def __init__(self, context: interfaces.context.ContextInterface, config_path: str) -> None:
        super().__init__(context, config_path)
        self._requirements = []  # type: List[Tuple[str, interfaces.configuration.RequirementInterface]]
        self._banners = {}  # type: symbol_cache.BannersType

    @property
    def banners(self) -> symbol_cache.BannersType:
        """Creates a cached copy of the results, but only it's been requested"""
        if not self._banners:
            if not self.banner_cache:
                raise RuntimeError("Cache has not been properly defined for {}".format(self.__class__.__name__))
            self._banners = self.banner_cache.load_banners()
        return self._banners

    def __call__(self,
                 context: interfaces.context.ContextInterface,
                 config_path: str,
                 requirement: interfaces.configuration.RequirementInterface,
                 progress_callback: validity.ProgressCallback = None) -> None:
        """Searches for SymbolRequirements and attempt to populate them"""

        # Bomb out early if our details haven't been configured
        if self.symbol_class is None:
            return

        self._requirements = self.find_requirements(
            context,
            config_path,
            requirement, (requirements.TranslationLayerRequirement, requirements.SymbolRequirement),
            shortcut = False)

        for (sub_path, requirement) in self._requirements:
            parent_path = interfaces.configuration.parent_path(sub_path)

            if (isinstance(requirement, requirements.SymbolRequirement)
                    and requirement.unsatisfied(context, parent_path)):
                for (tl_sub_path, tl_requirement) in self._requirements:
                    tl_parent_path = interfaces.configuration.parent_path(tl_sub_path)
                    # Find the TranslationLayer sibling to the SymbolRequirement
                    if (isinstance(tl_requirement, requirements.TranslationLayerRequirement)
                            and tl_parent_path == parent_path):
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
        and scans the layer for banners"""

        # Bomb out early if there's no banners
        if not self.banners:
            return

        mss = scanners.MultiStringScanner([x for x in self.banners if x is not None])

        layer = context.memory[layer_name]

        # Check if the Stacker has already found what we're looking for
        if layer.config.get(self.banner_config_key, None):
            banner_list = [(0, bytes(layer.config[self.banner_config_key], 'latin-1'))]  # type: Iterable[Any]
        else:
            # Swap to the physical layer for scanning
            # TODO: Fix this so it works for layers other than just Intel
            layer = context.memory[layer.config['memory_layer']]
            banner_list = layer.scan(context = context, scanner = mss, progress_callback = progress_callback)

        for _, banner in banner_list:
            vollog.debug("Identified banner: {}".format(repr(banner)))
            symbol_files = self.banners.get(banner, None)
            if symbol_files:
                isf_path = symbol_files[0]
                vollog.debug("Using symbol library: {}".format(symbol_files[0]))
                clazz = self.symbol_class
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
            vollog.debug("No existing banners found")
            # TODO: Fallback to generic regex search?
