import os
import pathlib
import pickle

from volatility.framework import interfaces, constants
from volatility.framework.symbols import intermed

cached_linuxbanner_filepath = os.path.join(constants.CACHE_PATH, "linux_banners.cache")


class LinuxSymbolCache(interfaces.automagic.AutomagicInterface):
    """Class to run through all Linux symbols tables and cache their banners"""

    def __call__(self, context, config_path, configurable, progress_callback = None):
        """Runs the automagic over the configurable"""
        # We only need to be called once, so no recursion necessary

        linuxbanners = {}
        if os.path.exists(cached_linuxbanner_filepath):
            with open(cached_linuxbanner_filepath, "rb") as f:
                # We use pickle over JSON because we're dealing with bytes objects
                linuxbanners.update(pickle.load(f))

        search_paths = constants.SYMBOL_BASEPATHS
        cacheables = []
        for path in search_paths:
            # Favour specific name, over uncompressed JSON (user-editable), over compressed JSON over uncompressed files
            for extension in ['.json', '.json.xz']:
                # Hopefully these will not be large lists, otherwise this might be slow
                cacheables += [x.as_uri() for x in
                               pathlib.Path(path).joinpath('linux').resolve().rglob('*' + extension)]

        for banner in linuxbanners:
            for json_file in linuxbanners[banner]:
                if json_file in cacheables:
                    cacheables.remove(json_file)

        total = len(cacheables)
        for current in range(total):
            progress_callback(current / total)
            isf_url = cacheables[current]

            try:
                # Loading the symbol table will be very slow until it's been validated
                isf = intermed.IntermediateSymbolTable(context, config_path, "temp", isf_url)

                # We should store the banner against the filename
                # We don't bother with the hash (it'll likely take too long to validate)
                # but we should check at least that the banner matches on load.
                banner = isf.get_symbol("linux_banner").constant_data
                bannerlist = linuxbanners.get(banner, [])
                bannerlist.append(isf_url)
                linuxbanners[banner] = bannerlist
            except KeyError:
                pass

        with open(cached_linuxbanner_filepath, "wb") as f:
            pickle.dump(linuxbanners, f)
