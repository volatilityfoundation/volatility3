# This file is Copyright 2022 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

import logging
import urllib.parse
from typing import Optional, Any, List

try:
    import s3fs
    HAS_S3FS = True
except ImportError:
    HAS_S3FS = False

try:
    import gcsfs
    HAS_GCSFS = True
except ImportError:
    HAS_GCSFS = False

from volatility3.framework import exceptions
from volatility3.framework.layers import resources

vollog = logging.getLogger(__file__)

if HAS_S3FS:

    class S3FileSystemHandler(resources.VolatilityHandler):
            
            @classmethod
            def non_cached_schemes(cls) -> List[str]:
                return ["s3"]

            @staticmethod
            def default_open(req: urllib.request.Request) -> Optional[Any]:
                """Handles the request if it's the s3 scheme."""
                if req.type == "s3":
                    object_uri = "://".join(req.full_url.split("://")[1:])
                    return s3fs.S3FileSystem().open(object_uri)
                return None

if HAS_GCSFS:
    
    class GSFileSystemHandler(resources.VolatilityHandler):
            @classmethod
            def non_cached_schemes(cls) -> List[str]:
                return ["gs"]
            
            @staticmethod
            def default_open(req: urllib.request.Request) -> Optional[Any]:
                """Handles the request if it's the gs scheme."""
                if req.type == "gs":
                    object_uri = "://".join(req.full_url.split("://")[1:])
                    return gcsfs.GCSFileSystem().open(object_uri)
                return None