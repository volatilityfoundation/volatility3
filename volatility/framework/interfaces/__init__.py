"""The interfaces module contains the API interface for the core volatility framework

These interfaces should help developers attempting to write components for the main framework
and help them understand how to use the internal components of volatility to write plugins.
"""

# Import the submodules we want people to be able to use without importing them themselves
# This will also avoid namespace issues, because people can use interfaces.layers to
# avoid clashing with the layers package
from volatility.framework.interfaces import context, layers, objects, configuration, \
    plugins, renderers, symbols, automagic
