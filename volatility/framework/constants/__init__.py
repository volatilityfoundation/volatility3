# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl_v1.0
#
"""Volatility 3 Constants

Stores all the constant values that are generally fixed throughout volatility
This includes default scanning block sizes, etc."""
import enum
import os.path
import sys
from typing import Optional, Callable

import volatility.framework.constants.linux
import volatility.framework.constants.windows

PLUGINS_PATH = [
    os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "plugins")),
    os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "plugins"))
]
"""Default list of paths to load plugins from (volatility/plugins and volatility/framework/plugins)"""

SYMBOL_BASEPATHS = [
    os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "symbols")),
    os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "symbols"))
]
"""Default list of paths to load symbols from (volatility/symbols and volatility/framework/symbols)"""

BANG = "!"
"""Constant used to delimit table names from type names when referring to a symbol"""

PACKAGE_VERSION = "3.0.0_alpha1"
"""The canonical version of the volatility package"""

AUTOMAGIC_CONFIG_PATH = 'automagic'
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

if sys.platform == 'windows':
    CACHE_PATH = os.path.join(os.environ.get("APPDATA", os.path.expanduser("~")), "volatility3")
os.makedirs(CACHE_PATH, exist_ok = True)

LINUX_BANNERS_PATH = os.path.join(CACHE_PATH, "linux_banners.cache")
""""Default location to record information about available linux banners"""

MAC_BANNERS_PATH = os.path.join(CACHE_PATH, "mac_banners.cache")
""""Default location to record information about available mac banners"""

ProgressCallback = Optional[Callable[[float, str], None]]
"""Type information for ProgressCallback objects"""


class Parallelism(enum.IntEnum):
    """An enumeration listing the different types of parallelism applied to volatility"""
    Off = 0
    Threading = 1
    Multiprocessing = 2


PARALLELISM = Parallelism.Off
"""Default value to the parallelism setting used throughout volatility"""
