# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
"""Defines the plugin architecture.

This is the namespace for all volatility plugins,
and determines the path for loading plugins

NOTE: This file is important for core plugins to run (which certain components such as the windows registry layers)
are dependent upon, please DO NOT alter or remove this file unless you know the consequences of doing so.

The framework is configured this way to allow plugin developers/users to override any plugin functionality whether
existing or new.
"""
from volatility3.framework import constants

__path__ = constants.PLUGINS_PATH
