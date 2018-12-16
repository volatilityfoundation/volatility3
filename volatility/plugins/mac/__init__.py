"""All Mac-related plugins"""

import os

from volatility.framework import constants

# This is necessary to ensure the core plugins are available, whilst still be overridable
plugin_path_components = __name__.split('.')[2:]
__path__ = [os.path.join(x, *plugin_path_components) for x in constants.PLUGINS_PATH]
