# This file is Copyright 2025 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
import logging
from volatility3.framework import interfaces, deprecation
from volatility3.plugins.linux.malware import hidden_modules

vollog = logging.getLogger(__name__)


class Hidden_modules(
    interfaces.plugins.PluginInterface,
    deprecation.PluginRenameClass,
    replacement_class=hidden_modules.Hidden_modules,
    removal_date="2026-06-07",
):
    """Carves memory to find hidden kernel modules (deprecated)."""

    _required_framework_version = (2, 25, 0)
    _version = (3, 0, 2)
