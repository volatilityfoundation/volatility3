# This file was contributed to the Volatility Framework Version 3.
# Copyright (C) 2018 Volatility Foundation.
#
# THE LICENSED WORK IS PROVIDED UNDER THE TERMS OF THE Volatility Contributors
# Public License V1.0("LICENSE") AS FIRST COMPLETED BY: Volatility Foundation,
# Inc. ANY USE, PUBLIC DISPLAY, PUBLIC PERFORMANCE, REPRODUCTION OR DISTRIBUTION
# OF, OR PREPARATION OF SUBSEQUENT WORKS, DERIVATIVE WORKS OR DERIVED WORKS BASED
# ON, THE LICENSED WORK CONSTITUTES RECIPIENT'S ACCEPTANCE OF THIS LICENSE AND ITS
# TERMS, WHETHER OR NOT SUCH RECIPIENT READS THE TERMS OF THE LICENSE. "LICENSED
# WORK,” “RECIPIENT" AND “DISTRIBUTOR" ARE DEFINED IN THE LICENSE. A COPY OF THE
# LICENSE IS LOCATED IN THE TEXT FILE ENTITLED "LICENSE.txt" ACCOMPANYING THE
# CONTENTS OF THIS FILE. IF A COPY OF THE LICENSE DOES NOT ACCOMPANY THIS FILE, A
# COPY OF THE LICENSE MAY ALSO BE OBTAINED AT THE FOLLOWING WEB SITE:
# https://www.volatilityfoundation.org/license/vcpl_v1.0
#
# Software distributed under the License is distributed on an "AS IS" basis,
# WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License for the
# specific language governing rights and limitations under the License.
#
"""Volatility 3 Constants

Stores all the constant values that are generally fixed throughout volatility
This includes default scanning block sizes, etc."""
import os.path
import sys
from typing import Optional, Callable

import volatility.framework.constants.linux
import volatility.framework.constants.windows

PLUGINS_PATH = [
    os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "plugins")),
    os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "plugins"))
]
SYMBOL_BASEPATHS = [
    os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "symbols")),
    os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "symbols"))
]
BANG = "!"
PACKAGE_VERSION = "3.0.0_alpha1"
AUTOMAGIC_CONFIG_PATH = 'automagic'

LOGLEVEL_V = 9
LOGLEVEL_VV = 8
LOGLEVEL_VVV = 7
LOGLEVEL_VVVV = 6

if sys.platform == 'windows':
    CACHE_PATH = os.path.join(os.environ.get("APPDATA", os.path.expanduser("~")), "volatility3")
else:
    CACHE_PATH = os.path.join(os.path.expanduser("~"), ".cache", "volatility3")
os.makedirs(CACHE_PATH, exist_ok = True)

LINUX_BANNERS_PATH = os.path.join(CACHE_PATH, "linux_banners.cache")
MAC_BANNERS_PATH = os.path.join(CACHE_PATH, "mac_banners.cache")

ProgressCallback = Optional[Callable[[float, str], None]]

PARALLELISM_OFF = 0
PARALLELISM_THREADING = 1
PARALLELISM_MULTIPROCESSING = 2

PARALLELISM = PARALLELISM_MULTIPROCESSING
