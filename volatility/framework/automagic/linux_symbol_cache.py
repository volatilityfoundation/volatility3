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

LinuxBanners = typing.Dict[bytes, typing.List[str]]


class LinuxSymbolCache(interfaces.automagic.AutomagicInterface):
    """Runs through all Linux symbols tables and caches their banners"""

    # Since this is necessary for ConstructionMagic, we set a lower priority
    # The user would run it eventually either way, but running it first means it can be used that run
    priority = 0

    @classmethod
    def load_linux_banners(cls) -> LinuxBanners:
        linux_banners = {}  # type: LinuxBanners
        if os.path.exists(constants.LINUX_BANNERS_PATH):
            with open(constants.LINUX_BANNERS_PATH, "rb") as f:
                # We use pickle over JSON because we're dealing with bytes objects
                linux_banners.update(pickle.load(f))

        # Remove possibilities that can't exist locally.
        remove_banners = []
        for banner in linux_banners:
            for path in linux_banners[banner]:
                url = urllib.parse.urlparse(path)
                if url.scheme == 'file' and not os.path.exists(urllib.request.url2pathname(url.path)):
                    vollog.log(constants.LOGLEVEL_V,
                               "Removing cached path {} for banner {}: file does not exist".format(path, banner))
                    linux_banners[banner].remove(path)
            if not linux_banners[banner]:
                remove_banners.append(banner)
        for remove_banner in remove_banners:
            del linux_banners[remove_banner]
        return linux_banners

    @classmethod
    def save_linux_banners(cls, linux_banners):

        with open(constants.LINUX_BANNERS_PATH, "wb") as f:
            pickle.dump(linux_banners, f)

    def __call__(self, context, config_path, configurable, progress_callback = None):
        """Runs the automagic over the configurable"""
        # We only need to be called once, so no recursion necessary
        linuxbanners = self.load_linux_banners()

        cacheables = list(intermed.IntermediateSymbolTable.file_symbol_url("linux"))

        for banner in linuxbanners:
            for json_file in linuxbanners[banner]:
                if json_file in cacheables:
                    cacheables.remove(json_file)

        total = len(cacheables)
        if total > 0:
            vollog.info("Building linux caches...")
        for current in range(total):
            progress_callback(current * 100 / total, "Building linux caches")
            isf_url = cacheables[current]

            try:
                # Loading the symbol table will be very slow until it's been validated
                isf = intermed.IntermediateSymbolTable(context, config_path, "temp", isf_url, validate = False)

                # We should store the banner against the filename
                # We don't bother with the hash (it'll likely take too long to validate)
                # but we should check at least that the banner matches on load.
                banner = isf.get_symbol("linux_banner").constant_data
                vollog.log(constants.LOGLEVEL_V, "Caching banner {} for file {}".format(banner, isf_url))
                bannerlist = linuxbanners.get(banner, [])
                bannerlist.append(isf_url)
                linuxbanners[banner] = bannerlist
            except exceptions.SymbolError:
                pass

            # Rewrite the cached linuxbanners each run, since writing is faster than the cache validation portion
            self.save_linux_banners(linuxbanners)
