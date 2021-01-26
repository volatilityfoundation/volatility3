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
import urllib.parse
import urllib.request
import zipfile
from typing import Optional, Any, IO
from urllib import error

from volatility3 import framework
from volatility3.framework import constants

try:
    import magic

    HAS_MAGIC = True
except ImportError:
    HAS_MAGIC = False

try:
    # Import so that the handler is found by the framework.class_subclasses callc
    import smb.SMBHandler  # lgtm [py/unused-import]
except ImportError:
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


class ResourceAccessor(object):
    """Object for openning URLs as files (downloading locally first if
    necessary)"""

    list_handlers = True

    def __init__(self,
                 progress_callback: Optional[constants.ProgressCallback] = None,
                 context: Optional[ssl.SSLContext] = None) -> None:
        """Creates a resource accessor.

        Note: context is an SSL context, not a volatility context
        """
        self._progress_callback = progress_callback
        self._context = context
        self._handlers = list(framework.class_subclasses(urllib.request.BaseHandler))
        if self.list_handlers:
            vollog.log(constants.LOGLEVEL_VVV,
                       "Available URL handlers: {}".format(", ".join([x.__name__ for x in self._handlers])))
            self.__class__.list_handlers = False

    def uses_cache(self, url: str) -> bool:
        """Determines whether a URLs contents should be cached"""
        parsed_url = urllib.parse.urlparse(url)

        return not parsed_url.scheme in ['file', 'jar']

    # Current urllib.request.urlopen returns Any, so we do the same
    def open(self, url: str, mode: str = "rb") -> Any:
        """Returns a file-like object for a particular URL opened in mode.

        If the file is remote, it will be downloaded and locally cached
        """
        urllib.request.install_opener(urllib.request.build_opener(*self._handlers))

        try:
            fp = urllib.request.urlopen(url, context = self._context)
        except error.URLError as excp:
            if excp.args:
                # TODO: As of python3.7 this can be removed
                unverified_retrieval = (hasattr(ssl, "SSLCertVerificationError") and isinstance(
                    excp.args[0], ssl.SSLCertVerificationError)) or (isinstance(excp.args[0], ssl.SSLError) and
                                                                     excp.args[0].reason == "CERTIFICATE_VERIFY_FAILED")
                if unverified_retrieval:
                    vollog.warning("SSL certificate verification failed: attempting UNVERIFIED retrieval")
                    non_verifying_ctx = ssl.SSLContext()
                    non_verifying_ctx.check_hostname = False
                    non_verifying_ctx.verify_mode = ssl.CERT_NONE
                    fp = urllib.request.urlopen(url, context = non_verifying_ctx)
                else:
                    raise excp
            else:
                raise excp

        with contextlib.closing(fp) as fp:
            # Cache the file locally

            if not self.uses_cache(url):
                # ZipExtFiles (files in zips) cannot seek, so must be cached in order to use and/or decompress
                curfile = urllib.request.urlopen(url, context = self._context)
            else:
                # TODO: find a way to check if we already have this file (look at http headers?)
                block_size = 1028 * 8
                temp_filename = os.path.join(
                    constants.CACHE_PATH,
                    "data_" + hashlib.sha512(bytes(url, 'raw_unicode_escape')).hexdigest() + ".cache")

                if not os.path.exists(temp_filename):
                    vollog.debug("Caching file at: {}".format(temp_filename))

                    try:
                        content_length = fp.info().get('Content-Length', -1)
                    except AttributeError:
                        # If our fp doesn't have an info member, carry on gracefully
                        content_length = -1
                    cache_file = open(temp_filename, "wb")

                    count = 0
                    block = fp.read(block_size)
                    while block:
                        count += len(block)
                        if self._progress_callback:
                            self._progress_callback(count * 100 / max(count, int(content_length)),
                                                    "Reading file {}".format(url))
                        cache_file.write(block)
                        block = fp.read(block_size)
                    cache_file.close()
                # Re-open the cache with a different mode
                curfile = open(temp_filename, mode = "rb")

        # Determine whether the file is a particular type of file, and if so, open it as such
        IMPORTED_MAGIC = False
        if HAS_MAGIC:
            stop = False
            while not stop:
                detected = None
                try:
                    # Detect the content
                    detected = magic.detect_from_fobj(curfile)
                    IMPORTED_MAGIC = True
                    # This is because python-magic and file provide a magic module
                    # Only file's python has magic.detect_from_fobj
                except (AttributeError, IOError):
                    pass

                if detected:
                    if detected.mime_type == 'application/x-xz':
                        curfile = cascadeCloseFile(lzma.LZMAFile(curfile, mode), curfile)
                    elif detected.mime_type == 'application/x-bzip2':
                        curfile = cascadeCloseFile(bz2.BZ2File(curfile, mode), curfile)
                    elif detected.mime_type == 'application/x-gzip':
                        curfile = cascadeCloseFile(gzip.GzipFile(fileobj = curfile, mode = mode), curfile)
                    if detected.mime_type in ['application/x-xz', 'application/x-bzip2', 'application/x-gzip']:
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
                    curfile = cascadeCloseFile(gzip.GzipFile(fileobj = curfile, mode = mode), curfile)
                else:
                    stop = True

        # Fallback in case the file doesn't exist
        if curfile is None:
            raise ValueError("URL does not reference an openable file")
        return curfile


class JarHandler(urllib.request.BaseHandler):
    """Handles the jar scheme for URIs.

    Reference used for the schema syntax:
    http://docs.netkernel.org/book/view/book:mod:reference/doc:layer1:schemes:jar

    Actual reference (found from https://www.w3.org/wiki/UriSchemes/jar) seemed not to return:
    http://developer.java.sun.com/developer/onlineTraining/protocolhandlers/
    """

    @staticmethod
    def default_open(req: urllib.request.Request) -> Optional[Any]:
        """Handles the request if it's the jar scheme."""
        if req.type == 'jar':
            subscheme, remainder = req.full_url.split(":")[1], ":".join(req.full_url.split(":")[2:])
            if subscheme != 'file':
                vollog.log(constants.LOGLEVEL_VVV, "Unsupported jar subscheme {}".format(subscheme))
                return None

            zipsplit = remainder.split("!")
            if len(zipsplit) != 2:
                vollog.log(constants.LOGLEVEL_VVV,
                           "Path did not contain exactly one fragment indicator: {}".format(remainder))
                return None

            zippath, filepath = zipsplit
            return zipfile.ZipFile(zippath).open(filepath)
        return None
