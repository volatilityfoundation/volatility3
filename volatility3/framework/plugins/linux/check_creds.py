# This file is Copyright 2025 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
import logging
from volatility3.framework import interfaces, deprecation
from volatility3.plugins.linux.malware import check_creds

vollog = logging.getLogger(__name__)


class Check_creds(
    interfaces.plugins.PluginInterface,
    deprecation.PluginRenameClass,
    replacement_class=check_creds.Check_creds,
    removal_date="2026-06-07",
):
    """Checks if any processes are sharing credential structures (deprecated)."""

    _required_framework_version = (2, 0, 0)
    _version = (2, 0, 2)
