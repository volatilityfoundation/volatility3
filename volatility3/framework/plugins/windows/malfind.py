# This file is Copyright 2025 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
import logging
from volatility3.framework import interfaces, deprecation
from volatility3.plugins.windows.malware import malfind

vollog = logging.getLogger(__name__)


class Malfind(
    interfaces.plugins.PluginInterface,
    deprecation.PluginRenameClass,
    replacement_class=malfind.Malfind,
    removal_date="2026-06-07",
):
    """Lists process memory ranges that potentially contain injected code (deprecated)."""

    _required_framework_version = (2, 22, 0)
    _version = (1, 1, 0)
