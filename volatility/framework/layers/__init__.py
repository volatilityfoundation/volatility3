import bz2
import contextlib
import gzip
import hashlib
import logging
import lzma
import os
import urllib.parse
import urllib.request
import zipfile
from urllib import request

try:
    import magic

    IMPORTED_MAGIC = True
except ImportError:
    IMPORTED_MAGIC = False

try:
    import smb.SMBHandler
except ImportError:
    pass

from volatility import framework
from volatility.framework import constants
from volatility.framework.interfaces.layers import IMPORTED_MAGIC
from volatility.framework.layers import intel, lime, physical, segmented, vmware

vollog = logging.getLogger(__name__)


class ResourceAccessor(object):
    """Object for openning URLs as files (downloading locally first if necessary)"""

    def __init__(self, progress_callback = None, context = None):
        """Creates a resource accessor

        Note: context is an SSL context, not a volatility context
        """
        self._progress_callback = progress_callback
        self._context = context
        self._cached_files = []
        self._handlers = list(framework.class_subclasses(request.BaseHandler))
        vollog.log(constants.LOGLEVEL_VVV,
                   "Available URL handlers: {}".format(", ".join([x.__name__ for x in self._handlers])))

    def open(self, url, mode = "rb"):
        """Returns a file-like object for a particular URL opened in mode"""
        urllib.request.install_opener(urllib.request.build_opener(*self._handlers))

        with contextlib.closing(urllib.request.urlopen(url, context = self._context)) as fp:
            # Cache the file locally
            parsed_url = urllib.parse.urlparse(url)

            if parsed_url.scheme == 'file':
                # ZipExtFiles (files in zips) cannot seek, so must be cached in order to use and/or decompress
                curfile = urllib.request.urlopen(url, context = self._context)
            else:
                # TODO: find a way to check if we already have this file (look at http headers?)
                block_size = 1028 * 8
                temp_filename = os.path.join(constants.CACHE_PATH,
                                             "data_" + hashlib.sha512(bytes(url, 'latin-1')).hexdigest())

                if not temp_filename in self._cached_files or not os.path.exists(temp_filename):
                    vollog.info("Caching file at: {}".format(temp_filename))

                    content_length = fp.info().get('Content-Length', -1)
                    cache_file = open(temp_filename, "wb")

                    count = 0
                    while True:
                        block = fp.read(block_size)
                        count += len(block)
                        if not block:
                            break
                        if self._progress_callback:
                            self._progress_callback(count / max(count, int(content_length)),
                                                    "Reading file {}".format(url))
                        cache_file.write(block)
                    cache_file.close()
                    # Globally stash the file as cached this python session
                    self._cached_files += [temp_filename]
                # Re-open the cache with a different mode
                curfile = open(temp_filename, mode = "rb")

        # Determine whether the file is a particular type of file, and if so, open it as such
        if IMPORTED_MAGIC:
            while True:
                try:
                    # Detect the content
                    detected = magic.detect_from_fobj(curfile)
                except:
                    break

                if detected:
                    if detected.mime_type == 'application/x-xz':
                        curfile = lzma.LZMAFile(curfile, mode)
                    elif detected.mime_type == 'application/x-bzip2':
                        curfile = bz2.BZ2File(curfile, mode)
                    elif detected.mime_type == 'application/x-gzip':
                        curfile = gzip.GzipFile(fileobj = curfile, mode = mode)
                    else:
                        break
                else:
                    break

                # Read and rewind to ensure we're inside any compressed file layers
                curfile.read(1)
                curfile.seek(0)
        else:
            # Somewhat of a hack, but prevents a hard dependency on the magic module
            url_path = parsed_url.path
            while True:
                if url_path.endswith(".xz"):
                    curfile = lzma.LZMAFile(curfile, mode)
                elif url_path.endswith(".bz2"):
                    curfile = bz2.BZ2File(curfile, mode)
                elif url_path.endswith(".gz"):
                    curfile = gzip.GzipFile(fileobj = curfile, mode = mode)
                else:
                    break
                url_path = ".".join(url_path.split(".")[:-1])

        # Fallback in case the file doesn't exist
        if curfile is None:
            raise ValueError("URL does not reference an openable file")
        return curfile


class JarHandler(request.BaseHandler):
    """Handles the jar scheme for URIs

    Reference used for the schema syntax:
    http://docs.netkernel.org/book/view/book:mod:reference/doc:layer1:schemes:jar

    Actual reference (found from https://www.w3.org/wiki/UriSchemes/jar) seemed not to return:
    http://developer.java.sun.com/developer/onlineTraining/protocolhandlers/
    """

    def default_open(self, req):
        """Handles the request if it's the jar scheme"""
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
