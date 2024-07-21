# This file is Copyright 2024 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

# This module attempts to locate skeleton-key like function hooks.
# It does this by locating the CSystems array through a variety of methods,
# and then validating the entry for RC4 HMAC (0x17 / 23)
#
# For a thorough walkthrough on how the R&D was performed to develop this plugin,
# please see our blogpost here:
#
# https://volatility-labs.blogspot.com/2021/10/memory-forensics-r-illustrated.html

import logging

from volatility3.framework import symbols, interfaces
from volatility3.framework.configuration import requirements
from volatility3.plugins.windows import svclist, svcscan
from volatility3.framework.symbols.windows import versions

vollog = logging.getLogger(__name__)


class SvcDiff(svcscan.SvcScan):
    """Compares services found through list walking versus scanning to find rootkits"""

    _required_framework_version = (2, 4, 0)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._enumeration_method = self.service_diff

    @classmethod
    def get_requirements(cls):
        # Since we're calling the plugin, make sure we have the plugin's requirements
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Windows kernel",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.VersionRequirement(
                name="svclist", component=svclist.SvcList, version=(1, 0, 0)
            ),
            requirements.VersionRequirement(
                name="svcscan", component=svcscan.SvcScan, version=(3, 0, 0)
            ),
        ]

    @classmethod
    def service_diff(
        cls,
        context: interfaces.context.ContextInterface,
        layer_name: str,
        symbol_table: str,
        service_table_name: str,
        service_binary_dll_map,
        filter_func,
    ):
        """
        On Windows 10 version 15063+ 64bit Windows memory samples, walk the services list
        and scan for services then report differences
        """
        if not symbols.symbol_table_is_64bit(
            context, symbol_table
        ) or not versions.is_win10_15063_or_later(
            context=context, symbol_table=symbol_table
        ):
            vollog.warning(
                "This plugin only supports Windows 10 version 15063+ 64bit Windows memory samples"
            )
            return

        from_scan = set()
        from_list = set()
        records = {}

        # collect unique service names from scanning
        for service in svcscan.SvcScan.service_scan(
            context,
            layer_name,
            symbol_table,
            service_table_name,
            service_binary_dll_map,
            filter_func,
        ):
            from_scan.add(service[6])
            records[service[6]] = service

        # collect services from listing walking
        for service in svclist.SvcList.service_list(
            context,
            layer_name,
            symbol_table,
            service_table_name,
            service_binary_dll_map,
            filter_func,
        ):
            from_list.add(service[6])

        # report services found from scanning but not list walking
        for hidden_service in from_scan - from_list:
            yield records[hidden_service]
