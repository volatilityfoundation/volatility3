# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl_v1.0
#
"""All Windows OS plugins.

NOTE: This file is important for core plugins to run (which certain components such as the windows registry layers)
are dependent upon, please DO NOT alter or remove this file unless you know the consequences of doing so.

The framework is configured this way to allow plugin developers/users to override any plugin functionality whether
existing or new.
"""

import os

from volatility.framework import constants

# This is necessary to ensure the core plugins are available, whilst still be overridable
plugin_path_components = __name__.split('.')[2:]
__path__ = [os.path.join(x, *plugin_path_components) for x in constants.PLUGINS_PATH]
