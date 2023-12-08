# This file is Copyright 2020 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0

import json
import logging
import ntpath
import os
import re
from typing import List, Dict, Union

from volatility3.framework import (
    renderers,
    interfaces,
    objects,
    exceptions,
    constants,
    layers,
)
from volatility3.framework.configuration import requirements
from volatility3.framework.renderers import format_hints
from volatility3.framework.symbols.windows.extensions import registry
from volatility3.plugins.windows import pslist
from volatility3.plugins.windows.registry import hivelist

vollog = logging.getLogger(__name__)


def find_sid_re(
    sid_string, sid_re_list
) -> Union[str, interfaces.renderers.BaseAbsentValue]:
    for reg, name in sid_re_list:
        if reg.search(sid_string):
            return name
    return renderers.NotAvailableValue()


class GetSIDs(interfaces.plugins.PluginInterface):
    """Print the SIDs owning each process"""

    _version = (1, 0, 0)
    _required_framework_version = (2, 0, 0)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
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

        # Get all the sids from the json file.
        with open(sids_json_file_name, "r") as file_handle:
            sids_json_data = json.load(file_handle)
            self.servicesids = sids_json_data["service sids"]
            self.well_known_sids = sids_json_data["well known"]

            # Compile all the sids regex.
            self.well_known_sid_re = [
                (re.compile(c_list[0]), c_list[1])
                for c_list in sids_json_data["sids re"]
            ]

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
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
            requirements.PluginRequirement(
                name="hivelist", plugin=hivelist.HiveList, version=(1, 0, 0)
            ),
        ]

    def lookup_user_sids(self) -> Dict[str, str]:
        """
        Enumerate the registry for all the users.

        Returns:
            An dictionary of {sid: user name}
        """

        key = "Microsoft\\Windows NT\\CurrentVersion\\ProfileList"
        val = "ProfileImagePath"
        kernel = self.context.modules[self.config["kernel"]]

        sids = {}
        for hive in hivelist.HiveList.list_hives(
            context=self.context,
            base_config_path=self.config_path,
            layer_name=kernel.layer_name,
            symbol_table=kernel.symbol_table_name,
            filter_string="config\\software",
            hive_offsets=None,
        ):
            try:
                for subkey in hive.get_key(key).get_subkeys():
                    sid = str(subkey.get_name())
                    path = ""
                    for node in subkey.get_values():
                        try:
                            value_node_name = node.get_name() or "(Default)"
                        except (
                            exceptions.InvalidAddressException,
                            layers.registry.RegistryFormatException,
                        ) as excp:
                            continue
                        try:
                            value_data = node.decode_data()
                            if isinstance(value_data, int):
                                value_data = format_hints.MultiTypeData(
                                    value_data, encoding="utf-8"
                                )
                            elif (
                                registry.RegValueTypes(node.Type)
                                == registry.RegValueTypes.REG_BINARY
                            ):
                                value_data = format_hints.MultiTypeData(
                                    value_data, show_hex=True
                                )
                            elif (
                                registry.RegValueTypes(node.Type)
                                == registry.RegValueTypes.REG_MULTI_SZ
                            ):
                                value_data = format_hints.MultiTypeData(
                                    value_data, encoding="utf-16-le", split_nulls=True
                                )
                            else:
                                value_data = format_hints.MultiTypeData(
                                    value_data, encoding="utf-16-le"
                                )
                            if value_node_name == val:
                                path = str(value_data).replace("\\x00", "")[:-1]
                                user = ntpath.basename(path)
                                sids[sid] = user
                        except (
                            ValueError,
                            exceptions.InvalidAddressException,
                            layers.registry.RegistryFormatException,
                        ) as excp:
                            continue
            except (KeyError, exceptions.InvalidAddressException):
                continue

        return sids

    def _generator(self, procs):
        user_sids = self.lookup_user_sids()

        # Go all over the process list, get the token
        for task in procs:
            # Make sure we have a valid token
            try:
                token = task.Token.dereference().cast("_TOKEN")
            except exceptions.InvalidAddressException:
                token = False

            if not token or not isinstance(token, interfaces.objects.ObjectInterface):
                yield (
                    0,
                    [
                        int(task.UniqueProcessId),
                        str(task.ImageFileName),
                        "Token unreadable",
                        "",
                    ],
                )
                continue

            # Go all over the sids and try to translate them with one of the tables we have
            for sid_string in token.get_sids():
                if sid_string in self.well_known_sids:
                    sid_name = self.well_known_sids[sid_string]
                elif sid_string in self.servicesids:
                    sid_name = self.servicesids[sid_string]
                elif sid_string in user_sids:
                    sid_name = user_sids[sid_string]
                else:
                    sid_name_re = find_sid_re(sid_string, self.well_known_sid_re)
                    if sid_name_re:
                        sid_name = sid_name_re
                    else:
                        sid_name = ""

                yield (
                    0,
                    (
                        task.UniqueProcessId,
                        objects.utility.array_to_string(task.ImageFileName),
                        sid_string,
                        sid_name,
                    ),
                )

    def run(self):
        filter_func = pslist.PsList.create_pid_filter(self.config.get("pid", None))
        kernel = self.context.modules[self.config["kernel"]]

        return renderers.TreeGrid(
            [("PID", int), ("Process", str), ("SID", str), ("Name", str)],
            self._generator(
                pslist.PsList.list_processes(
                    context=self.context,
                    layer_name=kernel.layer_name,
                    symbol_table=kernel.symbol_table_name,
                    filter_funcs=[filter_func],
                )
            ),
        )
