# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0

import json
import logging
import os
from typing import List

from volatility3.framework import renderers, interfaces, objects, exceptions, constants
from volatility3.framework.configuration import requirements
from volatility3.plugins.windows import pslist

vollog = logging.getLogger(__name__)


class Privs(interfaces.plugins.PluginInterface):
    """Lists process token privileges"""

    _version = (1, 2, 0)
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
            temp_json = json.load(file_handle)["privileges"]
            self.privilege_info = {
                int(priv_num): temp_json[priv_num] for priv_num in temp_json
            }

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        # Since we're calling the plugin, make sure we have the plugin's requirements
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Windows kernel",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.ListRequirement(
                name="pid",
                description="Filter on specific process IDs",
                element_type=int,
                optional=True,
            ),
            requirements.PluginRequirement(
                name="pslist", plugin=pslist.PsList, version=(2, 0, 0)
            ),
        ]

    def _generator(self, procs):
        for task in procs:
            try:
                process_token = task.Token.dereference().cast("_TOKEN")
            except exceptions.InvalidAddressException:
                vollog.log(constants.LOGLEVEL_VVV, "Skip invalid token.")
                continue

            for value, present, enabled, default in process_token.privileges():
                # Skip privileges whose bit positions cannot be
                # translated to a privilege name
                if not self.privilege_info.get(int(value)):
                    vollog.log(
                        constants.LOGLEVEL_VVV, f"Skip invalid privilege ({value})."
                    )
                    continue

                name, desc = self.privilege_info.get(int(value))

                # Set the attributes
                attributes = []
                if present:
                    attributes.append("Present")
                if enabled:
                    attributes.append("Enabled")
                if default:
                    attributes.append("Default")

                yield (
                    0,
                    [
                        int(task.UniqueProcessId),
                        objects.utility.array_to_string(task.ImageFileName),
                        int(value),
                        str(name),
                        ",".join(attributes),
                        str(desc),
                    ],
                )

    def run(self):
        filter_func = pslist.PsList.create_pid_filter(self.config.get("pid", None))
        kernel = self.context.modules[self.config["kernel"]]

        return renderers.TreeGrid(
            [
                ("PID", int),
                ("Process", str),
                ("Value", int),
                ("Privilege", str),
                ("Attributes", str),
                ("Description", str),
            ],
            self._generator(
                pslist.PsList.list_processes(
                    context=self.context,
                    layer_name=kernel.layer_name,
                    symbol_table=kernel.symbol_table_name,
                    filter_funcs=[filter_func],
                )
            ),
        )
