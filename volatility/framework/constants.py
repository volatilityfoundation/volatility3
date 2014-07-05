"""Volatility 3 Constants

Stores all the constant values that are generally fixed throughout volatiltiy
This includes default scanning block sizes, etc."""

import os.path

PLUGINS_PATH = [os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "plugins"))]
