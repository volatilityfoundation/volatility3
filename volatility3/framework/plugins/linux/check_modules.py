# This file is Copyright 2025 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
import logging
from volatility3.framework import interfaces, deprecation
from volatility3.plugins.linux.malware import check_modules

vollog = logging.getLogger(__name__)


class Check_modules(
    interfaces.plugins.PluginInterface,
    deprecation.PluginRenameClass,
    replacement_class=check_modules.Check_modules,
    removal_date="2026-06-07",
):
    """Compares module list to sysfs info, if available (deprecated)."""

    _version = (3, 0, 1)
    _required_framework_version = (2, 0, 0)
