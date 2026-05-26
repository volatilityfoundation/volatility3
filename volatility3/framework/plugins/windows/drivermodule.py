# This file is Copyright 2025 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
import logging
from volatility3.framework import interfaces, deprecation
from volatility3.plugins.windows.malware import drivermodule

vollog = logging.getLogger(__name__)


class DriverModule(
    interfaces.plugins.PluginInterface,
    deprecation.PluginRenameClass,
    replacement_class=drivermodule.DriverModule,
    removal_date="2026-06-07",
):
    """Determines if any loaded drivers were hidden by a rootkit (deprecated)."""

    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 0)
