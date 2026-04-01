import logging
import struct
import datetime
from typing import Iterable, Optional

from volatility3.framework import interfaces, renderers, exceptions
from volatility3.framework.configuration import requirements
from volatility3.framework.layers import registry as registry_layer
from volatility3.framework.symbols.windows.extensions import registry
from volatility3.plugins.windows.registry import hivelist
from volatility3.framework.renderers import conversion

vollog = logging.getLogger(__name__)


class LastShutdown(interfaces.plugins.PluginInterface):
    """Extract last Windows shutdown time from registry"""

    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 0)

    @classmethod
    def get_requirements(cls):
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Windows kernel",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.VersionRequirement(
                name="hivelist",
                component=hivelist.HiveList,
                version=(2, 0, 0),
            ),
        ]

    @staticmethod
    def filetime_to_dt(filetime: int) -> datetime.datetime:
        return datetime.datetime(1601, 1, 1) + datetime.timedelta(
            microseconds=filetime / 10
        )

    @classmethod
    def get_key(
        cls, hive: registry_layer.RegistryHive, key_path: str
    ) -> Optional["registry.CM_KEY_NODE"]:
        try:
            return hive.get_key(key_path)
        except Exception:
            return None

    def _generator(self, syshive: registry_layer.RegistryHive) -> Iterable:

        if not syshive:
            return

        # try multiple controlsets (robust approach)
        for i in range(1, 5):

            key_path = f"ControlSet{i:03}\\Control\\Windows"

            key = self.get_key(syshive, key_path)

            if not key:
                continue

            for v in key.get_values():

                if v.get_name() == "ShutdownTime":

                    try:
                        data = syshive.read(v.Data + 4, v.DataLength)
                    except exceptions.InvalidAddressException:
                        continue

                    if not data or len(data) < 8:
                        continue

                    filetime = struct.unpack("<Q", data[:8])[0]
                    shutdown_time = conversion.wintime_to_datetime(filetime)

                    yield (0, (key_path, str(shutdown_time)))

    def run(self):

        syshive = None

        for hive in hivelist.HiveList.list_hives(
            context=self.context,
            base_config_path=self.config_path,
            kernel_module_name=self.config["kernel"],
        ):

            if hive.get_name().split("\\")[-1].upper() == "SYSTEM":
                syshive = hive

        return renderers.TreeGrid(
            [
                ("Registry Key", str),
                ("Last Shutdown Time", str),
            ],
            self._generator(syshive),
        )