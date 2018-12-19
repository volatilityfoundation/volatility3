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
import os
import pickle
import urllib
import urllib.parse
import urllib.request
from typing import Dict, List, Optional

from volatility.framework import constants, exceptions, interfaces
from volatility.framework.symbols import intermed

vollog = logging.getLogger(__name__)

BannersType = Dict[bytes, List[str]]


class SymbolBannerCache(interfaces.automagic.AutomagicInterface):
    """Runs through all symbols tables and caches their banners"""

    # Since this is necessary for ConstructionMagic, we set a lower priority
    # The user would run it eventually either way, but running it first means it can be used that run
    priority = 0

    os = None  # type: Optional[str]
    symbol_name = "banner_name"  # type: str
    banner_path = None  # type: Optional[str]

    @classmethod
    def load_banners(cls) -> BannersType:
        if not cls.banner_path:
            raise ValueError("Banner_path not appropriately set")
        banners = {}  # type: BannersType
        if os.path.exists(cls.banner_path):
            with open(cls.banner_path, "rb") as f:
                # We use pickle over JSON because we're dealing with bytes objects
                banners.update(pickle.load(f))

        # Remove possibilities that can't exist locally.
        remove_banners = []
        for banner in banners:
            for path in banners[banner]:
                url = urllib.parse.urlparse(path)
                if url.scheme == 'file' and not os.path.exists(urllib.request.url2pathname(url.path)):
                    vollog.log(constants.LOGLEVEL_V,
                               "Removing cached path {} for banner {}: file does not exist".format(path, banner))
                    banners[banner].remove(path)
                # This is probably excessive, but it's here if we need it
                # if url.scheme == 'jar':
                #     zip_file, zip_path = url.path.split("!")
                #     zip_file = urllib.parse.urlparse(zip_file).path
                #     if ((not os.path.exists(zip_file)) or (zip_path not in zipfile.ZipFile(zip_file).namelist())):
                #         vollog.log(constants.LOGLEVEL_V,
                #                    "Removing cached path {} for banner {}: file does not exist".format(path, banner))
                #         banners[banner].remove(path)

            if not banners[banner]:
                remove_banners.append(banner)
        for remove_banner in remove_banners:
            del banners[remove_banner]
        return banners

    @classmethod
    def save_banners(cls, banners):

        with open(cls.banner_path, "wb") as f:
            pickle.dump(banners, f)

    def __call__(self, context, config_path, configurable, progress_callback = None):
        """Runs the automagic over the configurable"""

        # Bomb out if we're just the generic interface
        if self.os is None:
            return

        # We only need to be called once, so no recursion necessary
        banners = self.load_banners()

        cacheables = list(intermed.IntermediateSymbolTable.file_symbol_url(self.os))

        for banner in banners:
            for json_file in banners[banner]:
                if json_file in cacheables:
                    cacheables.remove(json_file)

        total = len(cacheables)
        if total > 0:
            vollog.info("Building {} caches...".format(self.os))
        for current in range(total):
            progress_callback(current * 100 / total, "Building {} caches".format(self.os))
            isf_url = cacheables[current]

            try:
                # Loading the symbol table will be very slow until it's been validated
                isf = intermed.IntermediateSymbolTable(context, config_path, "temp", isf_url, validate = False)

                # We should store the banner against the filename
                # We don't bother with the hash (it'll likely take too long to validate)
                # but we should check at least that the banner matches on load.
                banner = isf.get_symbol(self.symbol_name).constant_data
                vollog.log(constants.LOGLEVEL_V, "Caching banner {} for file {}".format(banner, isf_url))
                bannerlist = banners.get(banner, [])
                bannerlist.append(isf_url)
                banners[banner] = bannerlist
            except exceptions.SymbolError:
                pass

            # Rewrite the cached banners each run, since writing is faster than the banner_cache validation portion
            self.save_banners(banners)
