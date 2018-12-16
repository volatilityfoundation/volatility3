"""Defines the plugin architecture

   This is the namespace for all volatility plugins,
   and determines the path for loading plugins

   NOTE: This file is important for core plugins to run (which certain components such as the windows registry layers)
   are dependent upon, please DO NOT alter or remove this file unless you know the consequences of doing so.

   The framework is configured this way to allow plugin developers/users to override any plugin functionality whether
   existing or new.
"""
from volatility.framework import constants

__path__ = constants.PLUGINS_PATH
