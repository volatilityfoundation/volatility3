# This file is Copyright 2020 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0

import hashlib
import json
import logging
import os
import struct
from typing import List

from volatility3.framework import renderers, interfaces, constants, exceptions
from volatility3.framework.configuration import requirements
from volatility3.plugins.windows.registry import hivelist

vollog = logging.getLogger(__name__)


def createservicesid(svc) -> str:
    """Calculate the Service SID"""
    uni = "".join([c + "\x00" for c in svc])
    sha = hashlib.sha1(
        uni.upper().encode("utf-8")
    ).digest()  # pylint: disable-msg=E1101
    dec = list()
    for i in range(5):
        ## The use of struct here is OK. It doesn't make much sense
        ## to leverage obj.Object inside this loop.
        dec.append(struct.unpack("<I", sha[i * 4 : i * 4 + 4])[0])
    return "S-1-5-80-" + "-".join([str(n) for n in dec])


class GetServiceSIDs(interfaces.plugins.PluginInterface):
    """Lists process token sids."""

    _version = (1, 0, 0)
    _required_framework_version = (2, 0, 0)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # Find the sids json path (or raise error if its not in the plugin directory).
        for plugin_dir in constants.PLUGINS_PATH:
            sids_json_file_name = os.path.join(
                plugin_dir, os.path.join("windows", "sids_and_privileges.json")
            )
            if os.path.exists(sids_json_file_name):
                break
        else:
            vollog.log(
                constants.LOGLEVEL_VVV,
                "sids_and_privileges.json file is missing plugin error",
            )
            raise RuntimeError(
                "The sids_and_privileges.json file missed from you plugin directory"
            )

        # Get service sids dictionary (we need only the service sids).
        with open(sids_json_file_name, "r") as file_handle:
            self.servicesids = json.load(file_handle)["service sids"]

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        # Since we're calling the plugin, make sure we have the plugin's requirements
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Windows kernel",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.PluginRequirement(
                name="hivelist", plugin=hivelist.HiveList, version=(1, 0, 0)
            ),
        ]

    def _generator(self):
        kernel = self.context.modules[self.config["kernel"]]
        # Get the system hive
        for hive in hivelist.HiveList.list_hives(
            context=self.context,
            base_config_path=self.config_path,
            layer_name=kernel.layer_name,
            symbol_table=kernel.symbol_table_name,
            filter_string="machine\\system",
            hive_offsets=None,
        ):
            # Get ControlSet\Services.
            try:
                services = hive.get_key(r"CurrentControlSet\Services")
            except (KeyError, exceptions.InvalidAddressException):
                try:
                    services = hive.get_key(r"ControlSet001\Services")
                except (KeyError, exceptions.InvalidAddressException):
                    continue

            if services:
                for s in services.get_subkeys():
                    if s.get_name() not in self.servicesids.values():
                        sid = createservicesid(s.get_name())
                        yield (0, (sid, s.get_name()))

    def run(self):
        return renderers.TreeGrid([("SID", str), ("Service", str)], self._generator())
