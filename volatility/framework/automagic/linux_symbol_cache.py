import logging
import os
import pickle
from urllib import parse

from volatility.framework import constants, exceptions, interfaces
from volatility.framework.symbols import intermed

vollog = logging.getLogger(__name__)


class LinuxSymbolCache(interfaces.automagic.AutomagicInterface):
    """Runs through all Linux symbols tables and caches their banners"""

    @classmethod
    def load_linux_banners(cls):
        linuxbanners = {}
        if os.path.exists(constants.LINUX_BANNERS_PATH):
            with open(constants.LINUX_BANNERS_PATH, "rb") as f:
                # We use pickle over JSON because we're dealing with bytes objects
                linuxbanners.update(pickle.load(f))

        # Remove possibilities that can't exist locally.
        for banner in linuxbanners:
            for path in linuxbanners[banner]:
                url = parse.urlparse(path)
                if url.scheme == 'file' and not os.path.exists(parse.unquote(url.path)):
                    vollog.log(constants.LOGLEVEL_V,
                               "Removing cached path {} for banner {}: files does not exist".format(path, banner))
                    linuxbanners[banner].remove(path)
        return linuxbanners

    @classmethod
    def save_linux_banners(cls, linuxbanners):
        with open(constants.LINUX_BANNERS_PATH, "wb") as f:
            pickle.dump(linuxbanners, f)

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
