# This file is Copyright 2020 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
import contextlib
import logging
from typing import List

from volatility3.framework import constants, exceptions, interfaces, objects, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.layers import registry
from volatility3.plugins.windows import pslist
from volatility3.plugins.windows.registry import hivelist

vollog = logging.getLogger(__name__)


class Envars(interfaces.plugins.PluginInterface):
    "Display process environment variables"

    _version = (1, 0, 0)
    _required_framework_version = (2, 0, 0)

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
            requirements.BooleanRequirement(
                name="silent",
                description="Suppress common and non-persistent variables",
                optional=True,
            ),
            requirements.VersionRequirement(
                name="pslist", component=pslist.PsList, version=(3, 0, 0)
            ),
            requirements.VersionRequirement(
                name="hivelist", component=hivelist.HiveList, version=(2, 0, 0)
            ),
        ]

    def _get_silent_vars(self) -> List[str]:
        """Enumerate persistent & common variables.

        This function collects the global (all users) and
        user-specific environment variables from the
        registry. Any variables in a process env block that
        does not exist in the persistent list was explicitly
        set with the SetEnvironmentVariable() API.
        """

        values = []

        for hive in hivelist.HiveList.list_hives(
            context=self.context,
            base_config_path=self.config_path,
            kernel_module_name=self.config["kernel"],
            hive_offsets=None,
        ):
            ## The global variables
            sys = None
            try:
                sys = hive.get_key(
                    "CurrentControlSet\\Control\\Session Manager\\Environment"
                )
            except (
                KeyError,
                registry.RegistryException,
            ):
                with contextlib.suppress(
                    KeyError,
                    registry.RegistryException,
                ):
                    sys = hive.get_key(
                        "ControlSet001\\Control\\Session Manager\\Environment"
                    )
            if sys:
                with contextlib.suppress(
                    KeyError,
                    registry.RegistryException,
                ):
                    for node in sys.get_values():
                        try:
                            value_node_name = node.get_name()
                            if value_node_name:
                                values.append(value_node_name)
                        except (
                            exceptions.InvalidAddressException,
                            registry.RegistryException,
                        ):
                            vollog.log(
                                constants.LOGLEVEL_VVV,
                                "Error while parsing global environment variables keys (some keys might be excluded)",
                            )
                            continue

            ntuser = None
            ## The user-specific variables
            with contextlib.suppress(
                KeyError,
                registry.RegistryException,
            ):
                ntuser = hive.get_key("Environment")
            if ntuser:
                with contextlib.suppress(
                    KeyError,
                    registry.RegistryException,
                ):
                    for node in ntuser.get_values():
                        try:
                            value_node_name = node.get_name()
                            if value_node_name:
                                values.append(value_node_name)
                        except (
                            exceptions.InvalidAddressException,
                            registry.RegistryException,
                        ):
                            vollog.log(
                                constants.LOGLEVEL_VVV,
                                "Error while parsing user environment variables keys (some keys might be excluded)",
                            )
                            continue

            ## The volatile user variables
            try:
                key = hive.get_key("Volatile Environment")
            except (
                KeyError,
                registry.RegistryException,
            ):
                continue
            try:
                for node in key.get_values():
                    try:
                        value_node_name = node.get_name()
                        if value_node_name:
                            values.append(value_node_name)
                    except (
                        exceptions.InvalidAddressException,
                        registry.RegistryException,
                    ):
                        vollog.log(
                            constants.LOGLEVEL_VVV,
                            "Error while parsing volatile environment variables keys (some keys might be excluded)",
                        )
                        continue
            except KeyError:
                continue

        ## These are variables set explicitly but are
        ## common enough to ignore safely.
        values.extend(
            [
                "ProgramFiles",
                "CommonProgramFiles",
                "SystemDrive",
                "SystemRoot",
                "ProgramData",
                "PUBLIC",
                "ALLUSERSPROFILE",
                "COMPUTERNAME",
                "SESSIONNAME",
                "USERNAME",
                "USERPROFILE",
                "PROMPT",
                "USERDOMAIN",
                "AppData",
                "CommonFiles",
                "CommonDesktop",
                "CommonProgramGroups",
                "CommonStartMenu",
                "CommonStartUp",
                "Cookies",
                "DesktopDirectory",
                "Favorites",
                "History",
                "NetHood",
                "PersonalDocuments",
                "RecycleBin",
                "StartMenu",
                "Templates",
                "AltStartup",
                "CommonFavorites",
                "ConnectionWizard",
                "DocAndSettingRoot",
                "InternetCache",
                "windir",
                "Path",
                "HOMEDRIVE",
                "PROCESSOR_ARCHITECTURE",
                "NUMBER_OF_PROCESSORS",
                "ProgramFiles(x86)",
                "CommonProgramFiles(x86)",
                "CommonProgramW6432",
                "PSModulePath",
                "PROCESSOR_IDENTIFIER",
                "FP_NO_HOST_CHECK",
                "LOCALAPPDATA",
                "TMP",
                "ProgramW6432",
            ]
        )

        return values

    def _generator(self, data):
        silent_vars = self._get_silent_vars() if self.config.get("SILENT") else []

        for task in data:
            for var, val in task.environment_variables():
                if var in silent_vars:
                    continue

                yield (
                    0,
                    (
                        int(task.UniqueProcessId),
                        str(objects.utility.array_to_string(task.ImageFileName)),
                        hex(task.get_peb().ProcessParameters.Environment.vol.offset),
                        str(var),
                        str(val),
                    ),
                )

    def run(self):
        filter_func = pslist.PsList.create_pid_filter(self.config.get("pid", None))

        return renderers.TreeGrid(
            [
                ("PID", int),
                ("Process", str),
                ("Block", str),
                ("Variable", str),
                ("Value", str),
            ],
            self._generator(
                pslist.PsList.list_processes(
                    context=self.context,
                    kernel_module_name=self.config["kernel"],
                    filter_func=filter_func,
                )
            ),
        )
