import logging
import os
import pickle
import typing
import urllib
import urllib.parse
import urllib.request

from volatility.framework import constants, exceptions, interfaces
from volatility.framework.symbols import intermed

vollog = logging.getLogger(__name__)

MacBanners = typing.Dict[bytes, typing.List[str]]

class MacSymbolCache(interfaces.automagic.AutomagicInterface):
    """Runs through all Mac symbols tables and caches their banners"""

    # Since this is necessary for ConstructionMagic, we set a lower priority
    # The user would run it eventually either way, but running it first means it can be used that run
    priority = 0

    @classmethod
    def load_mac_banners(cls) -> MacBanners:
        mac_banners = {}  # type: MacBanners
        if os.path.exists(constants.MAC_BANNERS_PATH):
            with open(constants.MAC_BANNERS_PATH, "rb") as f:
                # We use pickle over JSON because we're dealing with bytes objects
                mac_banners.update(pickle.load(f))

        # Remove possibilities that can't exist locally.
        remove_banners = []
        for banner in mac_banners:
            for path in mac_banners[banner]:
                url = urllib.parse.urlparse(path)
                if url.scheme == 'file' and not os.path.exists(urllib.request.url2pathname(url.path)):
                    vollog.log(constants.LOGLEVEL_V,
                               "Removing cached path {} for banner {}: file does not exist".format(path, banner))
                    mac_banners[banner].remove(path)
                # This is probably excessive, but it's here if we need it
                # if url.scheme == 'jar':
                #     zip_file, zip_path = url.path.split("!")
                #     zip_file = urllib.parse.urlparse(zip_file).path
                #     if ((not os.path.exists(zip_file)) or (zip_path not in zipfile.ZipFile(zip_file).namelist())):
                #         vollog.log(constants.LOGLEVEL_V,
                #                    "Removing cached path {} for banner {}: file does not exist".format(path, banner))
                #         mac_banners[banner].remove(path)

            if not mac_banners[banner]:
                remove_banners.append(banner)
        for remove_banner in remove_banners:
            del mac_banners[remove_banner]
        return mac_banners

    @classmethod
    def save_mac_banners(cls, mac_banners):

        with open(constants.MAC_BANNERS_PATH, "wb") as f:
            pickle.dump(mac_banners, f)

    def __call__(self, context, config_path, configurable, progress_callback = None):
        """Runs the automagic over the configurable"""
        # We only need to be called once, so no recursion necessary
        macbanners = self.load_mac_banners()

        cacheables = list(intermed.IntermediateSymbolTable.file_symbol_url("mac"))
        vollog.info("Building mac cacheables...".format(cacheables))

        for banner in macbanners:
            for json_file in macbanners[banner]:
                if json_file in cacheables:
                    cacheables.remove(json_file)

        total = len(cacheables)
        if total > 0:
            vollog.info("Building mac caches...")
        for current in range(total):
            #progress_callback(current * 100 / total, "Building mac caches")
            isf_url = cacheables[current]

            try:
                # Loading the symbol table will be very slow until it's been validated
                isf = intermed.IntermediateSymbolTable(context, config_path, "temp", isf_url, validate = False)

                # We should store the banner against the filename
                # We don't bother with the hash (it'll likely take too long to validate)
                # but we should check at least that the banner matches on load.
                banner = isf.get_symbol("version").constant_data
                vollog.log(constants.LOGLEVEL_V, "Caching banner {} for file {}".format(banner, isf_url))
                bannerlist = macbanners.get(banner, [])
                bannerlist.append(isf_url)
                macbanners[banner] = bannerlist
            except exceptions.SymbolError:
                pass

            vollog.debug("writing mac banners: {}".format(macbanners))

            # Rewrite the cached macbanners each run, since writing is faster than the cache validation portion
            self.save_mac_banners(macbanners)
