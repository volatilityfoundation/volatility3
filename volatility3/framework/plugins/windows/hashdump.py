# This file is Copyright 2025 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
import logging
from volatility3.framework import interfaces, deprecation
from volatility3.plugins.windows.registry import hashdump

vollog = logging.getLogger(__name__)


class Hashdump(
    interfaces.plugins.PluginInterface,
    deprecation.PluginRenameClass,
    replacement_class=hashdump.Hashdump,
    removal_date="2025-09-25",
):
    """Dumps user hashes from memory (deprecated)"""

    _required_framework_version = (2, 0, 0)
    _version = (1, 1, 1)
