# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
import base64
import gc
import json
import logging
import os
import pickle
import urllib
import urllib.parse
import urllib.request
import zipfile
from typing import Dict, List, Optional

from volatility3.framework import constants, exceptions, interfaces
from volatility3.framework.layers import resources
from volatility3.framework.symbols import intermed

vollog = logging.getLogger(__name__)

BannersType = Dict[bytes, List[str]]


class SymbolBannerCache(interfaces.automagic.AutomagicInterface):
    """Runs through all symbols tables and caches their banners."""

    # Since this is necessary for ConstructionMagic, we set a lower priority
    # The user would run it eventually either way, but running it first means it can be used that run
    priority = 0

    os: Optional[str] = None
    symbol_name: str = "banner_name"
    banner_path: Optional[str] = None

    @classmethod
    def load_banners(cls) -> BannersType:
        if not cls.banner_path:
            raise ValueError("Banner_path not appropriately set")
        banners: BannersType = {}
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
                    vollog.log(
                        constants.LOGLEVEL_VV, "Removing cached path {} for banner {}: file does not exist".format(
                            path, str(banner or b'', 'latin-1')))
                    banners[banner].remove(path)
                # This is probably excessive, but it's here if we need it
                if url.scheme == 'jar':
                    zip_file, zip_path = url.path.split("!")
                    zip_file = urllib.parse.urlparse(zip_file).path
                    if ((not os.path.exists(zip_file)) or (zip_path not in zipfile.ZipFile(zip_file).namelist())):
                        vollog.log(constants.LOGLEVEL_VV,
                                   "Removing cached path {} for banner {}: file does not exist".format(path, banner))
                        banners[banner].remove(path)

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
        """Runs the automagic over the configurable."""

        # Bomb out if we're just the generic interface
        if self.os is None:
            return

        # We only need to be called once, so no recursion necessary
        banners = self.load_banners()

        cacheables = self.find_new_banner_files(banners, self.os)

        new_banners = self.read_new_banners(context, config_path, cacheables, self.symbol_name, self.os,
                                            progress_callback)

        # Add in any new banners to the existing list
        for new_banner in new_banners:
            banner_list = banners.get(new_banner, [])
            banners[new_banner] = list(set(banner_list + new_banners[new_banner]))

        # Do remote banners *after* the JSON loading, so that it doesn't pull down all the remote JSON
        self.remote_banners(banners, self.os)

        # Rewrite the cached banners each run, since writing is faster than the banner_cache validation portion
        self.save_banners(banners)

        if progress_callback is not None:
            progress_callback(100, f"Built {self.os} caches")

    @classmethod
    def read_new_banners(cls, context: interfaces.context.ContextInterface, config_path: str, new_urls: List[str],
                         symbol_name: str, operating_system: str = None,
                         progress_callback = None) -> Optional[Dict[bytes, List[str]]]:
        """Reads the any new banners for the OS in question"""
        if operating_system is None:
            return None

        banners = {}

        total = len(new_urls)
        if total > 0:
            vollog.info(f"Building {operating_system} caches...")
        for current in range(total):
            if progress_callback is not None:
                progress_callback(current * 100 / total, f"Building {operating_system} caches")
            isf_url = new_urls[current]

            isf = None
            try:
                # Loading the symbol table will be very slow until it's been validated
                isf = intermed.IntermediateSymbolTable(context, config_path, "temp", isf_url, validate = False)

                # We should store the banner against the filename
                # We don't bother with the hash (it'll likely take too long to validate)
                # but we should check at least that the banner matches on load.
                banner = isf.get_symbol(symbol_name).constant_data
                vollog.log(constants.LOGLEVEL_VV, f"Caching banner {banner} for file {isf_url}")

                bannerlist = banners.get(banner, [])
                bannerlist.append(isf_url)
                banners[banner] = bannerlist
            except exceptions.SymbolError:
                pass
            except json.JSONDecodeError:
                vollog.log(constants.LOGLEVEL_VV, f"Caching file {isf_url} failed due to JSON error")
            finally:
                # Get rid of the loaded file, in case it sits in memory
                if isf:
                    del isf
                    gc.collect()
        return banners

    @classmethod
    def find_new_banner_files(cls, banners: Dict[bytes, List[str]], operating_system: str) -> List[str]:
        """Gathers all files and remove existing banners"""
        cacheables = list(intermed.IntermediateSymbolTable.file_symbol_url(operating_system))
        for banner in banners:
            for json_file in banners[banner]:
                if json_file in cacheables:
                    cacheables.remove(json_file)
        return cacheables

    @classmethod
    def remote_banners(cls, banners: Dict[bytes, List[str]], operating_system = None, banner_location = None):
        """Adds remote URLs to the banner list"""
        if operating_system is None:
            return None

        if banner_location is None:
            banner_location = constants.REMOTE_ISF_URL

        if not constants.OFFLINE and banner_location is not None:
            try:
                rbf = RemoteBannerFormat(banner_location)
                rbf.process(banners, operating_system)
            except urllib.error.URLError:
                vollog.debug(f"Unable to download remote banner list from {banner_location}")


class RemoteBannerFormat:
    def __init__(self, location: str):
        self._location = location
        with resources.ResourceAccessor().open(url = location) as fp:
            self._data = json.load(fp)
        if not self._verify():
            raise ValueError("Unsupported version for remote banner list format")

    def _verify(self) -> bool:
        version = self._data.get('version', 0)
        if version in [1]:
            setattr(self, 'process', getattr(self, f'process_v{version}'))
            return True
        return False

    def process(self, banners: Dict[bytes, List[str]], operating_system: Optional[str]):
        raise ValueError("Banner List version not verified")

    def process_v1(self, banners: Dict[bytes, List[str]], operating_system: Optional[str]):
        if operating_system in self._data:
            for banner in self._data[operating_system]:
                binary_banner = base64.b64decode(banner)
                file_list = banners.get(binary_banner, [])
                for value in self._data[operating_system][banner]:
                    if value not in file_list:
                        file_list = file_list + [value]
                    banners[binary_banner] = file_list
        if 'additional' in self._data:
            for location in self._data['additional']:
                try:
                    subrbf = RemoteBannerFormat(location)
                    subrbf.process(banners, operating_system)
                except IOError:
                    vollog.debug(f"Remote file not found: {location}")
        return banners
