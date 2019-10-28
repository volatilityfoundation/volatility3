# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
"""All Mac-related plugins.

NOTE: This file is important for core plugins to run (which certain components such as the windows registry layers)
are dependent upon, please DO NOT alter or remove this file unless you know the consequences of doing so.

The framework is configured this way to allow plugin developers/users to override any plugin functionality whether
existing or new.

When overriding the plugins directory, you must include a file like this in any subdirectories that may be necessary.
"""
import os
import sys

# This is necessary to ensure the core plugins are available, whilst still be overridable
parent_module, module_name = ".".join(__name__.split(".")[:-1]), __name__.split(".")[-1]
__path__ = [os.path.join(x, module_name) for x in sys.modules[parent_module].__path__]
