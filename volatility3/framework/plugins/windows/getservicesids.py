# This file is Copyright 2020 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0

import hashlib
import json
import logging
import struct
from importlib import resources
from typing import List

from volatility3.framework import renderers, interfaces, exceptions
from volatility3.framework.configuration import requirements
from volatility3.framework.layers import registry
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
    return "S-1-5-80-" + "-".join(str(n) for n in dec)


class GetServiceSIDs(interfaces.plugins.PluginInterface):
    """Lists process token sids."""

    _version = (1, 0, 0)
    _required_framework_version = (2, 0, 0)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        with resources.open_text(
            "volatility3.data", "sids_and_privileges.json"
        ) as file_handle:
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
                name="hivelist", plugin=hivelist.HiveList, version=(2, 0, 0)
            ),
        ]

    def _generator(self):
        # Get the system hive
        for hive in hivelist.HiveList.list_hives(
            context=self.context,
            base_config_path=self.config_path,
            kernel_module_name=self.config["kernel"],
            filter_string="machine\\system",
            hive_offsets=None,
        ):
            # Get ControlSet\Services.
            try:
                services = hive.get_key(r"CurrentControlSet\Services")
            except (
                KeyError,
                exceptions.InvalidAddressException,
                registry.RegistryException,
            ):
                try:
                    services = hive.get_key(r"ControlSet001\Services")
                except (
                    KeyError,
                    exceptions.InvalidAddressException,
                    registry.RegistryException,
                ):
                    continue

            if services:
                for s in services.get_subkeys():
                    try:
                        sid_name = s.get_name()
                    except (
                        exceptions.InvalidAddressException,
                        registry.RegistryException,
                    ):
                        continue

                    if sid_name not in self.servicesids.values():
                        sid = createservicesid(sid_name)
                        yield (0, (sid, sid_name))

    def run(self):
        return renderers.TreeGrid([("SID", str), ("Service", str)], self._generator())
