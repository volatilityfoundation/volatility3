"""Defines the plugin architecture

   This is the namespace for all volatility plugins,
   and determines the path for loading plugins
"""
import volatility.framework.constants as constants

__path__ = constants.PLUGINS_PATH
