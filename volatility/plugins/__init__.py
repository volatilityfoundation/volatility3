"""Defines the plugin architecture

   This is the namespace for all volatility plugins,
   and determines the path for loading plugins
"""
from volatility.framework import constants

if not __path__:
    __path__ = constants.PLUGINS_PATH
