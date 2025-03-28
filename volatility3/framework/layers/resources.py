# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

import bz2
import contextlib
import gzip
import hashlib
import logging
import lzma
import os
import ssl
import sys
import urllib.parse
import urllib.request
import zipfile
from typing import Any, IO, List, Optional
from urllib import error

from volatility3 import framework
from volatility3.framework import constants, exceptions

try:
    import magic

    HAS_MAGIC = True
except ImportError:
    HAS_MAGIC = False

try:
    # Import so that the handler is found by the framework.class_subclasses callc
    from smb import SMBHandler as SMBHandler  # lgtm [py/unused-import]
except ImportError:
    # If we fail to import this, it means that SMB handling won't be available
    pass

vollog = logging.getLogger(__name__)


# TODO: Type-annotating the ResourceAccessor.open method is difficult because HTTPResponse is not actually an IO[Any] type
#   fix this


def cascadeCloseFile(new_fp: IO[bytes], original_fp: IO[bytes]) -> IO[bytes]:
    """Really horrible solution for ensuring files aren't left open

    Args:
        new_fp: The file pointer constructed based on the original file pointer
        original_fp: The original file pointer that should be closed when the new file pointer is closed, but isn't
    """

    def close():
        original_fp.close()
        return new_fp.__class__.close(new_fp)

    new_fp.close = close
    return new_fp


class ResourceAccessor:
    """Object for opening URLs as files (downloading locally first if
    necessary)"""

    list_handlers = True

    def __init__(
        self,
        progress_callback: Optional[constants.ProgressCallback] = None,
        context: Optional[ssl.SSLContext] = None,
        enable_cache: bool = True,
    ) -> None:
        """Creates a resource accessor.

        Note: context is an SSL context, not a volatility context
        """
        self._progress_callback = progress_callback
        self._context = context
        self._handlers = list(framework.class_subclasses(urllib.request.BaseHandler))
        self._enable_cache = enable_cache
        if self.list_handlers:
            vollog.log(
                constants.LOGLEVEL_VVV,
                f"Available URL handlers: {', '.join([x.__name__ for x in self._handlers])}",
            )
            self.__class__.list_handlers = False

    def uses_cache(self, url: str) -> bool:
        """Determines whether a URLs contents should be cached"""
        parsed_url = urllib.parse.urlparse(url)

        return (
            self._enable_cache and parsed_url.scheme not in self._non_cached_schemes()
        )

    @staticmethod
    def _non_cached_schemes() -> List[str]:
        """Returns the list of schemes not to be cached"""
        result = ["file"]
        for clazz in framework.class_subclasses(VolatilityHandler):
            result += clazz.non_cached_schemes()
        return result

    # Current urllib.request.urlopen returns Any, so we do the same
    def open(self, url: str, mode: str = "rb") -> Any:
        """Returns a file-like object for a particular URL opened in mode.

        If the file is remote, it will be downloaded and locally cached
        """
        urllib.request.install_opener(urllib.request.build_opener(*self._handlers))

        # Python bug 46654
        if sys.platform == "win32":
            # We only need to worry about UNC paths on windows, on linux they'd be smb:// and need pysmb or similar
            parsed_url = urllib.parse.urlparse(url, scheme="file")
            # Only worry about file scheme URLs, make sure that there's either a host or
            # the unparsing left an extra slash at the start (which will get lost with urlunparse)
            if parsed_url.scheme == "file" and (
                parsed_url.netloc or parsed_url.path.startswith("//")
            ):
                # Change the netloc to '/' and then prepend the netloc to the path
                # Urlunparse will remove extra initial slashes from path, hence setting netloc
                new_url = urllib.parse.urlunparse(
                    (
                        parsed_url.scheme,
                        "/",
                        "/" + parsed_url.netloc + parsed_url.path,
                        parsed_url.params,
                        parsed_url.query,
                        parsed_url.fragment,
                    )
                )
                vollog.log(
                    constants.LOGLEVEL_VVVV,
                    f"UNC path detected, converted path {url} to {new_url}",
                )
                url = new_url

        try:
            fp = urllib.request.urlopen(url, context=self._context)
        except error.URLError as excp:
            if excp.args:
                if isinstance(excp.args[0], ssl.SSLCertVerificationError):
                    vollog.warning(
                        "SSL certificate verification failed: attempting UNVERIFIED retrieval"
                    )
                    non_verifying_ctx = ssl.SSLContext()
                    non_verifying_ctx.check_hostname = False
                    non_verifying_ctx.verify_mode = ssl.CERT_NONE
                    fp = urllib.request.urlopen(url, context=non_verifying_ctx)
                else:
                    raise excp
            else:
                raise excp
        except ValueError as excp:
            # Reraise errors such as proxy auth errors as offline exception errors
            # Example Proxy auth error - ValueError: AbstractDigestAuthHandler does not support the following scheme: 'Negotiate'
            vollog.info(f"Cannot access {url} due to {excp} - Setting OFFLINE")
            constants.OFFLINE = True
            raise exceptions.OfflineException(url)
        except exceptions.OfflineException:
            vollog.info(f"Not accessing {url} in offline mode")
            raise

        with contextlib.closing(fp) as fp:
            # Cache the file locally

            if not self.uses_cache(url):
                # ZipExtFiles (files in zips) cannot seek, so must be cached in order to use and/or decompress
                curfile = urllib.request.urlopen(url, context=self._context)
            else:
                # TODO: find a way to check if we already have this file (look at http headers?)
                block_size = 1028 * 8
                temp_filename = os.path.join(
                    constants.CACHE_PATH,
                    "data_"
                    + hashlib.sha512(bytes(url, "raw_unicode_escape")).hexdigest()
                    + ".cache",
                )

                try:
                    content_length = int(fp.info().get("Content-Length", -1))
                except (AttributeError, ValueError):
                    # If our fp doesn't have an info member, carry on gracefully
                    content_length = -1

                if not os.path.exists(temp_filename):
                    vollog.debug(f"Caching file at: {temp_filename}")
                    cache_file_size = -1

                    try:
                        with open(temp_filename, "wb") as cache_file:
                            count = 0
                            block = fp.read(block_size)
                            while block:
                                count += len(block)
                                if self._progress_callback:
                                    self._progress_callback(
                                        count * 100 / max(count, int(content_length)),
                                        f"Reading file {url}",
                                    )
                                cache_file.write(block)
                                block = fp.read(block_size)
                            cache_file.seek(0, os.SEEK_END)
                            cache_file_size = cache_file.tell()
                    finally:
                        if cache_file_size < content_length:
                            os.remove(temp_filename)
                            raise ValueError("Cached file did not download completely")
                else:
                    vollog.debug(
                        f"Trying to use already cached file at: {temp_filename}"
                    )

                # Re-open the cache with a different mode
                # Since we don't want people thinking they're able to save to the cache file,
                # open it in read mode only and allow breakages to happen if they wanted to write
                curfile = open(temp_filename, mode="rb")

        # Validate the hash or delete the temp_filename and report an error

        # Determine whether the file is a particular type of file, and if so, open it as such
        IMPORTED_MAGIC = False
        if HAS_MAGIC:
            stop = False
            while not stop:
                detected = None
                with contextlib.suppress(AttributeError, IOError):
                    # Detect the content
                    detected = magic.detect_from_fobj(curfile)
                    IMPORTED_MAGIC = True
                    # This is because python-magic and file provide a magic module
                    # Only file's python has magic.detect_from_fobj

                if detected:
                    if detected.mime_type == "application/x-xz":
                        curfile = cascadeCloseFile(
                            lzma.LZMAFile(curfile, mode), curfile
                        )
                    elif detected.mime_type == "application/x-bzip2":
                        curfile = cascadeCloseFile(bz2.BZ2File(curfile, mode), curfile)
                    elif detected.mime_type == "application/x-gzip":
                        curfile = cascadeCloseFile(
                            gzip.GzipFile(fileobj=curfile, mode=mode), curfile
                        )
                    if detected.mime_type in [
                        "application/x-xz",
                        "application/x-bzip2",
                        "application/x-gzip",
                    ]:
                        # Read and rewind to ensure we're inside any compressed file layers
                        curfile.read(1)
                        curfile.seek(0)
                    else:
                        stop = True
                else:
                    stop = True

        if not IMPORTED_MAGIC:
            # Somewhat of a hack, but prevents a hard dependency on the magic module
            parsed_url = urllib.parse.urlparse(url)
            url_path = parsed_url.path
            stop = False
            while not stop:
                url_path_split = url_path.split(".")
                url_path_list, extension = url_path_split[:-1], url_path_split[-1]
                url_path = ".".join(url_path_list)
                if extension == "xz":
                    curfile = cascadeCloseFile(lzma.LZMAFile(curfile, mode), curfile)
                elif extension == "bz2":
                    curfile = cascadeCloseFile(bz2.BZ2File(curfile, mode), curfile)
                elif extension == "gz":
                    curfile = cascadeCloseFile(
                        gzip.GzipFile(fileobj=curfile, mode=mode), curfile
                    )
                else:
                    stop = True

        # Fallback in case the file doesn't exist
        if curfile is None:
            raise ValueError("URL does not reference an openable file")
        return curfile


class VolatilityHandler(urllib.request.BaseHandler):
    @classmethod
    def non_cached_schemes(cls) -> List[str]:
        return []


class JarHandler(VolatilityHandler):
    """Handles the jar scheme for URIs.

    Reference used for the schema syntax:
    http://docs.netkernel.org/book/view/book:mod:reference/doc:layer1:schemes:jar

    Actual reference (found from https://www.w3.org/wiki/UriSchemes/jar) seemed not to return:
    http://developer.java.sun.com/developer/onlineTraining/protocolhandlers/
    """

    @classmethod
    def non_cached_schemes(cls) -> List[str]:
        return ["jar"]

    @staticmethod
    def default_open(req: urllib.request.Request) -> Optional[Any]:
        """Handles the request if it's the jar scheme."""
        if req.type == "jar":
            subscheme, remainder = req.full_url.split(":")[1], ":".join(
                req.full_url.split(":")[2:]
            )
            if subscheme != "file":
                vollog.log(
                    constants.LOGLEVEL_VVV, f"Unsupported jar subscheme {subscheme}"
                )
                return None

            zipsplit = remainder.split("!")
            if len(zipsplit) != 2:
                vollog.log(
                    constants.LOGLEVEL_VVV,
                    f"Path did not contain exactly one fragment indicator: {remainder}",
                )
                return None

            zippath, filepath = zipsplit
            return zipfile.ZipFile(zippath).open(filepath)
        return None


class OfflineHandler(VolatilityHandler):
    @staticmethod
    def default_open(req: urllib.request.Request) -> Optional[Any]:
        if constants.OFFLINE and req.type in ["http", "https"]:
            raise exceptions.OfflineException(req.full_url)
        return None
