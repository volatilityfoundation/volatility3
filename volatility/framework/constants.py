"""Volatility 3 Constants

Stores all the constant values that are generally fixed throughout volatility
This includes default scanning block sizes, etc."""
import os.path

import sys

PLUGINS_PATH = [os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "plugins")),
                os.path.abspath(os.path.join(os.path.dirname(__file__), "plugins"))]
SYMBOL_BASEPATHS = [os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "symbols")),
                    os.path.abspath(os.path.join(os.path.dirname(__file__), "symbols"))]
BANG = "!"
PACKAGE_VERSION = "3.0.0_alpha1"
DISABLE_MULTITHREADED_SCANNING = False

LOGLEVEL_V = 9
LOGLEVEL_VV = 8
LOGLEVEL_VVV = 7

if sys.platform == 'windows':
    CACHE_PATH = os.path.join(os.environ.get("APPDATA", os.path.expanduser("~")), "volatility3")
else:
    CACHE_PATH = os.path.join(os.path.expanduser("~"), ".cache", "volatility3")
os.makedirs(CACHE_PATH, exist_ok = True)
