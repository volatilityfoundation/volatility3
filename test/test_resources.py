"""Caching of remote files by the ResourceAccessor."""

import hashlib
import io
import urllib.request

from volatility3.framework import constants
from volatility3.framework.layers import resources


def test_partial_download_is_not_left_in_the_cache(monkeypatch, tmp_path):
    """A download must only appear at its cache path once it is complete.

    A run killed mid-download used to leave a truncated cache file that
    every later run then trusted as complete.
    """
    url = "https://msdl.microsoft.com/download/symbols/ntkrnlmp.pdb"
    data = b"\x00" * 100000
    cache_file = tmp_path / (
        "data_"
        + hashlib.sha512(bytes(url, "raw_unicode_escape")).hexdigest()
        + ".cache"
    )
    seen_during_download = []

    class Download(io.BytesIO):
        def info(self):
            return {"Content-Length": str(len(data))}

        def read(self, size=-1):
            seen_during_download.append(cache_file.exists())
            return super().read(size)

    monkeypatch.setattr(constants, "CACHE_PATH", str(tmp_path))
    monkeypatch.setattr(
        urllib.request, "urlopen", lambda *args, **kwargs: Download(data)
    )

    with resources.ResourceAccessor().open(url) as fp:
        assert fp.read() == data

    assert not any(seen_during_download)
    assert [path.name for path in tmp_path.iterdir()] == [cache_file.name]
