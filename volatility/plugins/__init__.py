"""Defines the plugin architecture

   This is the namespace for all volatility plugins,
   and determines the path for loading plugins
"""
from volatility.framework import constants

__path__ = constants.PLUGINS_PATH
