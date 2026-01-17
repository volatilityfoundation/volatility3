# This file is Copyright 2025 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
import logging
from volatility3.framework import interfaces, deprecation
from volatility3.plugins.linux.malware import modxview

vollog = logging.getLogger(__name__)


class Modxview(
    interfaces.plugins.PluginInterface,
    deprecation.PluginRenameClass,
    replacement_class=modxview.Modxview,
    removal_date="2026-06-07",
):
    """Centralize lsmod, check_modules and hidden_modules results to efficiently \
spot modules presence and taints (deprecated)."""

    _version = (1, 0, 0)
    _required_framework_version = (2, 17, 0)
