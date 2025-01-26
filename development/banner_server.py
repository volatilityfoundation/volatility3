import argparse
import base64
import json
import logging
import os
import pathlib
import urllib

from volatility3.cli import PrintedProgress
from volatility3.framework import contexts, constants
from volatility3.framework.automagic import linux, mac

vollog = logging.getLogger(__name__)


class BannerCacheGenerator:

    def __init__(self, path: str, url_prefix: str):
        self._path = path
        self._url_prefix = url_prefix

    def convert_url(self, url):
        parsed = urllib.parse.urlparse(url)

        relpath = os.path.relpath(parsed.path, os.path.abspath(self._path))

        return urllib.parse.urljoin(self._url_prefix, relpath)

    def run(self):
        context = contexts.Context()
        json_output = {"version": 1}

        path = self._path
        filename = "*"

        for banner_cache in [linux.LinuxBannerCache, mac.MacBannerCache]:
            sub_path = banner_cache.os
            potentials = []
            for extension in constants.ISF_EXTENSIONS:
                # Hopefully these will not be large lists, otherwise this might be slow
                try:
                    for found in (
                        pathlib.Path(path)
                        .joinpath(sub_path)
                        .resolve()
                        .rglob(filename + extension)
                    ):
                        potentials.append(found.as_uri())
                except FileNotFoundError:
                    # If there's no linux symbols, don't cry about it
                    pass

            new_banners = banner_cache.read_new_banners(
                context,
                "BannerServer",
                potentials,
                banner_cache.symbol_name,
                banner_cache.os,
                progress_callback=PrintedProgress(),
            )
            result_banners = {}
            for new_banner in new_banners:
                # Only accept file schemes
                value = [
                    self.convert_url(url)
                    for url in new_banners[new_banner]
                    if urllib.parse.urlparse(url).scheme == "file"
                ]
                if value and new_banner:
                    # Convert files into URLs
                    result_banners[str(base64.b64encode(new_banner), "latin-1")] = value

            json_output[banner_cache.os] = result_banners

        output_path = os.path.join(self._path, "banners.json")
        with open(output_path, "w") as fp:
            vollog.warning(f"Banners file written to {output_path}")
            json.dump(json_output, fp)


if __name__ == "__main__":

    parser = argparse.ArgumentParser()
    parser.add_argument("--path", default=os.path.dirname(__file__))
    parser.add_argument(
        "--urlprefix",
        help="Web prefix that will eventually serve the ISF files",
        default="http://localhost/symbols",
    )

    args = parser.parse_args()

    bcg = BannerCacheGenerator(args.path, args.urlprefix)
    bcg.run()
