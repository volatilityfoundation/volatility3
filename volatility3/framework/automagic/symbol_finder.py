# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

import logging
import os
from typing import Any, Callable, Iterable, List, Optional, Tuple

from volatility3.framework import constants, interfaces, layers
from volatility3.framework.automagic import symbol_cache
from volatility3.framework.configuration import requirements
from volatility3.framework.layers import scanners

vollog = logging.getLogger(__name__)


class SymbolFinder(interfaces.automagic.AutomagicInterface):
    """Symbol loader based on signature strings."""

    priority = 40

    banner_config_key: str = "banner"
    operating_system: Optional[str] = None
    symbol_class: Optional[str] = None
    find_aslr: Optional[Callable] = None

    def __init__(
        self, context: interfaces.context.ContextInterface, config_path: str
    ) -> None:
        super().__init__(context, config_path)
        self._requirements: List[
            Tuple[str, interfaces.configuration.RequirementInterface]
        ] = []
        self._banners: symbol_cache.BannersType = {}

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.VersionRequirement(
                name="SQLiteCache",
                component=symbol_cache.SqliteCache,
                version=(1, 0, 0),
            )
        ]

    @property
    def banners(self) -> symbol_cache.BannersType:
        """Creates a cached copy of the results, but only it's been
        requested."""
        if not self._banners:
            identifiers_path = os.path.join(
                constants.CACHE_PATH, constants.IDENTIFIERS_FILENAME
            )
            cache = symbol_cache.SqliteCache(identifiers_path)
            self._banners = cache.get_identifier_dictionary(
                operating_system=self.operating_system
            )
        return self._banners

    def __call__(
        self,
        context: interfaces.context.ContextInterface,
        config_path: str,
        requirement: interfaces.configuration.RequirementInterface,
        progress_callback: constants.ProgressCallback = None,
    ) -> None:
        """Searches for SymbolTableRequirements and attempt to populate
        them."""

        # Bomb out early if our details haven't been configured
        if self.symbol_class is None:
            return

        self._requirements = self.find_requirements(
            context,
            config_path,
            requirement,
            (
                requirements.TranslationLayerRequirement,
                requirements.SymbolTableRequirement,
            ),
            shortcut=False,
        )

        for sub_path, requirement in self._requirements:
            parent_path = interfaces.configuration.parent_path(sub_path)

            if isinstance(
                requirement, requirements.SymbolTableRequirement
            ) and requirement.unsatisfied(context, parent_path):
                for tl_sub_path, tl_requirement in self._requirements:
                    tl_parent_path = interfaces.configuration.parent_path(tl_sub_path)
                    # Find the TranslationLayer sibling to the SymbolTableRequirement
                    if (
                        isinstance(
                            tl_requirement, requirements.TranslationLayerRequirement
                        )
                        and tl_parent_path == parent_path
                    ):
                        if context.config.get(tl_sub_path, None):
                            self._banner_scan(
                                context,
                                parent_path,
                                requirement,
                                context.config[tl_sub_path],
                                progress_callback,
                            )
                            break

    def _banner_scan(
        self,
        context: interfaces.context.ContextInterface,
        config_path: str,
        requirement: interfaces.configuration.ConstructableRequirementInterface,
        layer_name: str,
        progress_callback: constants.ProgressCallback = None,
    ) -> None:
        """Accepts a context, config_path and SymbolTableRequirement, with a
        constructed layer_name and scans the layer for banners."""

        # Bomb out early if there's no banners
        if not self.banners:
            return

        mss = scanners.MultiStringScanner([x for x in self.banners if x is not None])

        layer = context.layers[layer_name]

        # Check if the Stacker has already found what we're looking for
        if layer.config.get(self.banner_config_key, None):
            banner_list = [
                (0, bytes(layer.config[self.banner_config_key], "raw_unicode_escape"))
            ]  # type: Iterable[Any]
        else:
            # Swap to the physical layer for scanning
            # Only traverse down a layer if it's an intel layer
            # TODO: Fix this so it works for layers other than just Intel
            if isinstance(layer, layers.intel.Intel):
                layer = context.layers[layer.config["memory_layer"]]
            banner_list = layer.scan(
                context=context, scanner=mss, progress_callback=progress_callback
            )

        for _, banner in banner_list:
            vollog.debug(f"Identified banner: {repr(banner)}")
            symbol_files = self.banners.get(banner, None)
            if symbol_files:
                isf_path = symbol_files
                vollog.debug(f"Using symbol library: {symbol_files}")
                clazz = self.symbol_class
                # Set the discovered options
                path_join = interfaces.configuration.path_join
                context.config[
                    path_join(config_path, requirement.name, "class")
                ] = clazz
                context.config[
                    path_join(config_path, requirement.name, "isf_url")
                ] = isf_path
                context.config[
                    path_join(config_path, requirement.name, "symbol_mask")
                ] = layer.address_mask

                # Construct the appropriate symbol table
                requirement.construct(context, config_path)
                break
            else:
                vollog.debug(f"Symbol library path not found for: {banner}")
                # print("Kernel", banner, hex(banner_offset))
        else:
            vollog.debug("No existing banners found")
            # TODO: Fallback to generic regex search?
