# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
"""Volatility 3 Constants.

Stores all the constant values that are generally fixed throughout
volatility This includes default scanning block sizes, etc.
"""

import enum
import os.path
import sys
import warnings
from typing import Callable, Optional

from volatility3.framework.constants import linux as linux
from volatility3.framework.constants import windows as windows
from volatility3.framework.constants._version import (
    PACKAGE_VERSION as PACKAGE_VERSION,
    VERSION_MAJOR as VERSION_MAJOR,
    VERSION_MINOR as VERSION_MINOR,
    VERSION_PATCH as VERSION_PATCH,
    VERSION_SUFFIX as VERSION_SUFFIX,
)

REQUIRED_PYTHON_VERSION = (3, 8, 0)

PLUGINS_PATH = [
    os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "plugins")),
    os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "plugins")),
]
"""Default list of paths to load plugins from (volatility3/plugins and volatility3/framework/plugins)"""

SYMBOL_BASEPATHS = [
    os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "symbols")),
    os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "symbols")),
]
"""Default list of paths to load symbols from (volatility3/symbols and volatility3/framework/symbols)"""

ISF_EXTENSIONS = [".json", ".json.xz", ".json.gz", ".json.bz2"]
"""List of accepted extensions for ISF files"""

SYMBOL_SERVER_URL = "http://msdl.microsoft.com/download/symbols"

if hasattr(sys, "frozen") and sys.frozen:
    # Ensure we include the executable's directory as the base for plugins and symbols
    PLUGINS_PATH = [
        os.path.abspath(os.path.join(os.path.dirname(sys.executable), "plugins"))
    ] + PLUGINS_PATH
    SYMBOL_BASEPATHS = [
        os.path.abspath(os.path.join(os.path.dirname(sys.executable), "symbols"))
    ] + SYMBOL_BASEPATHS

BANG = "!"
"""Constant used to delimit table names from type names when referring to a symbol"""

AUTOMAGIC_CONFIG_PATH = "automagic"
"""The root section within the context configuration for automagic values"""

LOGLEVEL_INFO = 20
"""Logging level for information data, showed when use the requests any logging: -v"""
LOGLEVEL_DEBUG = 10
"""Logging level for debugging data, showed when the user requests more logging detail: -vv"""
LOGLEVEL_V = 9
"""Logging level for the lowest "extra" level of logging: -vvv"""
LOGLEVEL_VV = 8
"""Logging level for two levels of detail: -vvvv"""
LOGLEVEL_VVV = 7
"""Logging level for three levels of detail: -vvvvv"""
LOGLEVEL_VVVV = 6
"""Logging level for four levels of detail: -vvvvvv"""


CACHE_PATH = os.path.join(
    os.environ.get("XDG_CACHE_HOME") or os.path.join(os.path.expanduser("~"), ".cache"),
    "volatility3",
)
"""Default path to store cached data"""

SQLITE_CACHE_PERIOD = "-3 days"
"""SQLite time modifier for how long each item is valid in the cache for"""

if sys.platform == "win32":
    CACHE_PATH = os.path.realpath(
        os.path.join(os.environ.get("APPDATA", os.path.expanduser("~")), "volatility3")
    )
os.makedirs(CACHE_PATH, exist_ok=True)

IDENTIFIERS_FILENAME = "identifier.cache"
"""Default location to record information about available identifiers"""

CACHE_SQLITE_SCHEMA_VERSION = 1
"""Version for the sqlite3 cache schema"""

BUG_URL = "https://github.com/volatilityfoundation/volatility3/issues"

ProgressCallback = Optional[Callable[[float, str], None]]
"""Type information for ProgressCallback objects"""

OS_CATEGORIES = ["windows", "mac", "linux"]


class Parallelism(enum.IntEnum):
    """An enumeration listing the different types of parallelism applied to
    volatility."""

    Off = 0
    Threading = 1
    Multiprocessing = 2


PARALLELISM = Parallelism.Off
"""Default value to the parallelism setting used throughout volatility"""

ISF_MINIMUM_SUPPORTED = (2, 0, 0)
"""The minimum supported version of the Intermediate Symbol Format"""
ISF_MINIMUM_DEPRECATED = (3, 9, 9)
"""The highest version of the ISF that's deprecated (usually higher than supported)"""
OFFLINE = False
"""Whether to go online to retrieve missing/necessary JSON files"""

REMOTE_ISF_URL = None  # 'http://localhost:8000/banners.json'
"""Remote URL to query for a list of ISF addresses"""

DOWNLOAD_TIMEOUT = 30
"""Length of time (in seconds) to wait for another process to download a resource before using it"""

###
# DEPRECATED VALUES
###

_deprecated_LINUX_BANNERS_FILENAME = os.path.join(CACHE_PATH, "linux_banners.cache")
"""This value is deprecated and is no longer used within volatility"""

_deprecated_MAC_BANNERS_PATH = os.path.join(CACHE_PATH, "mac_banners.cache")
"""This value is deprecated and is no longer used within volatility"""

_deprecated_IDENTIFIERS_PATH = os.path.join(CACHE_PATH, IDENTIFIERS_FILENAME)
"""This value is deprecated in favour of CACHE_PATH joined to IDENTIFIER_FILENAME"""


def __getattr__(name):
    deprecated_tag = "_deprecated_"
    if name in [
        x[len(deprecated_tag) :] for x in globals() if x.startswith(deprecated_tag)
    ]:
        warnings.warn(f"{name} is deprecated", FutureWarning)
        return globals()[f"{deprecated_tag}{name}"]

    return getattr(__import__(__name__), name)
