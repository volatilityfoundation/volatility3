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

import volatility3.framework.constants.linux
import volatility3.framework.constants.windows

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

# We use the SemVer 2.0.0 versioning scheme
VERSION_MAJOR = 2  # Number of releases of the library with a breaking change
VERSION_MINOR = 5  # Number of changes that only add to the interface
VERSION_PATCH = 1  # Number of changes that do not change the interface
VERSION_SUFFIX = ""

# TODO: At version 2.0.0, remove the symbol_shift feature

PACKAGE_VERSION = (
    ".".join([str(x) for x in [VERSION_MAJOR, VERSION_MINOR, VERSION_PATCH]])
    + VERSION_SUFFIX
)
"""The canonical version of the volatility3 package"""

AUTOMAGIC_CONFIG_PATH = "automagic"
"""The root section within the context configuration for automagic values"""

LOGLEVEL_V = 9
"""Logging level for a single -v"""
LOGLEVEL_VV = 8
"""Logging level for -vv"""
LOGLEVEL_VVV = 7
"""Logging level for -vvv"""
LOGLEVEL_VVVV = 6
"""Logging level for -vvvv"""

CACHE_PATH = os.path.join(os.path.expanduser("~"), ".cache", "volatility3")
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
    return None
