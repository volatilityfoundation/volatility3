# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
"""The interfaces module contains the API interface for the core volatility
framework.

These interfaces should help developers attempting to write components
for the main framework and help them understand how to use the internal
components of volatility to write plugins.
"""

# Import the submodules we want people to be able to use without importing them themselves
# This will also avoid namespace issues, because people can use interfaces.layers to
# avoid clashing with the layers package
from volatility3.framework.interfaces import (
    renderers,
    configuration,
    context,
    layers,
    objects,
    plugins,
    symbols,
    automagic,
)
