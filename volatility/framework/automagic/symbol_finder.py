# This file was contributed to the Volatility Framework Version 3.
# Copyright (C) 2018 Volatility Foundation.
#
# THE LICENSED WORK IS PROVIDED UNDER THE TERMS OF THE Volatility Contributors
# Public License V1.0("LICENSE") AS FIRST COMPLETED BY: Volatility Foundation,
# Inc. ANY USE, PUBLIC DISPLAY, PUBLIC PERFORMANCE, REPRODUCTION OR DISTRIBUTION
# OF, OR PREPARATION OF SUBSEQUENT WORKS, DERIVATIVE WORKS OR DERIVED WORKS BASED
# ON, THE LICENSED WORK CONSTITUTES RECIPIENT'S ACCEPTANCE OF THIS LICENSE AND ITS
# TERMS, WHETHER OR NOT SUCH RECIPIENT READS THE TERMS OF THE LICENSE. "LICENSED
# WORK,” “RECIPIENT" AND “DISTRIBUTOR" ARE DEFINED IN THE LICENSE. A COPY OF THE
# LICENSE IS LOCATED IN THE TEXT FILE ENTITLED "LICENSE.txt" ACCOMPANYING THE
# CONTENTS OF THIS FILE. IF A COPY OF THE LICENSE DOES NOT ACCOMPANY THIS FILE, A
# COPY OF THE LICENSE MAY ALSO BE OBTAINED AT THE FOLLOWING WEB SITE:
# https://www.volatilityfoundation.org/license/vcpl_v1.0
#
# Software distributed under the License is distributed on an "AS IS" basis,
# WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License for the
# specific language governing rights and limitations under the License.
#

import logging
from typing import Any, Iterable, List, Tuple, Type, Optional

from volatility.framework import interfaces, constants
from volatility.framework.automagic import symbol_cache
from volatility.framework.configuration import requirements
from volatility.framework.layers import scanners

vollog = logging.getLogger(__name__)


class SymbolFinder(interfaces.automagic.AutomagicInterface):
    """Symbol loader based on signature strings"""
    priority = 40

    banner_config_key = "banner"  # type: str
    banner_cache = None  # type: Optional[Type[symbol_cache.SymbolBannerCache]]
    symbol_class = None  # type: Optional[str]

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
                 progress_callback: constants.ProgressCallback = None) -> None:
        """Searches for SymbolTableRequirements and attempt to populate them"""

        # Bomb out early if our details haven't been configured
        if self.symbol_class is None:
            return

        self._requirements = self.find_requirements(
            context,
            config_path,
            requirement, (requirements.TranslationLayerRequirement, requirements.SymbolTableRequirement),
            shortcut = False)

        for (sub_path, requirement) in self._requirements:
            parent_path = interfaces.configuration.parent_path(sub_path)

            if (isinstance(requirement, requirements.SymbolTableRequirement)
                    and requirement.unsatisfied(context, parent_path)):
                for (tl_sub_path, tl_requirement) in self._requirements:
                    tl_parent_path = interfaces.configuration.parent_path(tl_sub_path)
                    # Find the TranslationLayer sibling to the SymbolTableRequirement
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
                     progress_callback: constants.ProgressCallback = None) -> None:
        """Accepts a context, config_path and SymbolTableRequirement, with a constructed layer_name
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
