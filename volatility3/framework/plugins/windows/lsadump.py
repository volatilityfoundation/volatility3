# This file is Copyright 2025 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
import logging
from volatility3.framework import interfaces, deprecation
from volatility3.plugins.windows.registry import lsadump

vollog = logging.getLogger(__name__)


class Lsadump(
    interfaces.plugins.PluginInterface,
    deprecation.PluginRenameClass,
    replacement_class=lsadump.Lsadump,
    removal_date="2025-09-25",
):
    """Dumps lsa secrets from memory (deprecated)"""

    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 1)
