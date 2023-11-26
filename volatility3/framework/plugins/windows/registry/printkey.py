# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

import datetime
import logging
from typing import List, Sequence, Iterable, Tuple, Union

from volatility3.framework import objects, renderers, exceptions, interfaces, constants
from volatility3.framework.configuration import requirements
from volatility3.framework.layers.registry import RegistryHive, RegistryFormatException
from volatility3.framework.renderers import TreeGrid, conversion, format_hints
from volatility3.framework.symbols.windows.extensions.registry import RegValueTypes
from volatility3.plugins.windows.registry import hivelist

vollog = logging.getLogger(__name__)


class PrintKey(interfaces.plugins.PluginInterface):
    """Lists the registry keys under a hive or specific key value."""

    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Windows kernel",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.PluginRequirement(
                name="hivelist", plugin=hivelist.HiveList, version=(1, 0, 0)
            ),
            requirements.IntRequirement(
                name="offset", description="Hive Offset", default=None, optional=True
            ),
            requirements.StringRequirement(
                name="key", description="Key to start from", default=None, optional=True
            ),
            requirements.BooleanRequirement(
                name="recurse",
                description="Recurses through keys",
                default=False,
                optional=True,
            ),
        ]

    @classmethod
    def key_iterator(
        cls,
        hive: RegistryHive,
        node_path: Sequence[objects.StructType] = None,
        recurse: bool = False,
    ) -> Iterable[
        Tuple[
            int, bool, datetime.datetime, str, bool, interfaces.objects.ObjectInterface
        ]
    ]:
        """Walks through a set of nodes from a given node (last one in
        node_path). Avoids loops by not traversing into nodes already present
        in the node_path.

        Args:
            hive: The registry hive to walk
            node_path: The list of nodes that make up the
            recurse: Traverse down the node tree or stay only on the same level

        Yields:
            A tuple of results (depth, is_key, last write time, path, volatile, and the node).
        """
        if not node_path:
            node_path = [hive.get_node(hive.root_cell_offset)]
        if not isinstance(node_path, list) or len(node_path) < 1:
            vollog.warning("Hive walker was not passed a valid node_path (or None)")
            return None
        node = node_path[-1]
        key_path_items = [hive] + node_path[1:]
        key_path = "\\".join([k.get_name() for k in key_path_items])
        if node.vol.type_name.endswith(constants.BANG + "_CELL_DATA"):
            raise RegistryFormatException(
                hive.name, "Encountered _CELL_DATA instead of _CM_KEY_NODE"
            )
        last_write_time = conversion.wintime_to_datetime(node.LastWriteTime.QuadPart)

        for key_node in node.get_subkeys():
            result = (
                len(node_path),
                True,
                last_write_time,
                key_path,
                key_node.get_volatile(),
                key_node,
            )
            yield result

            if recurse:
                if key_node.vol.offset not in [x.vol.offset for x in node_path]:
                    try:
                        key_node.get_name()
                    except exceptions.InvalidAddressException as excp:
                        vollog.debug(excp)
                        continue

                    yield from cls.key_iterator(
                        hive, node_path + [key_node], recurse=recurse
                    )

        for value_node in node.get_values():
            result = (
                len(node_path),
                False,
                last_write_time,
                key_path,
                node.get_volatile(),
                value_node,
            )
            yield result

    def _printkey_iterator(
        self,
        hive: RegistryHive,
        node_path: Sequence[objects.StructType] = None,
        recurse: bool = False,
    ):
        """Method that wraps the more generic key_iterator, to provide output
        for printkey specifically.

        Args:
            hive: The registry hive to walk
            node_path: The list of nodes that make up the
            recurse: Traverse down the node tree or stay only on the same level

        Yields:
            The depth, and a tuple of results (last write time, hive offset, type, path, name, data and volatile)
        """
        for (
            depth,
            is_key,
            last_write_time,
            key_path,
            volatile,
            node,
        ) in self.key_iterator(hive, node_path, recurse):
            if is_key:
                try:
                    key_node_name = node.get_name()
                except (
                    exceptions.InvalidAddressException,
                    RegistryFormatException,
                ) as excp:
                    vollog.debug(excp)
                    key_node_name = renderers.UnreadableValue()

                # if the item is a subkey, use the LastWriteTime of that subkey
                last_write_time = conversion.wintime_to_datetime(
                    node.LastWriteTime.QuadPart
                )

                yield (
                    depth,
                    (
                        last_write_time,
                        renderers.format_hints.Hex(hive.hive_offset),
                        "Key",
                        key_path,
                        key_node_name,
                        renderers.NotApplicableValue(),
                        volatile,
                    ),
                )
            else:
                try:
                    value_node_name = node.get_name() or "(Default)"
                except (
                    exceptions.InvalidAddressException,
                    RegistryFormatException,
                ) as excp:
                    vollog.debug(excp)
                    value_node_name = renderers.UnreadableValue()

                try:
                    value_type = RegValueTypes(node.Type).name
                except (
                    exceptions.InvalidAddressException,
                    RegistryFormatException,
                ) as excp:
                    vollog.debug(excp)
                    value_type = renderers.UnreadableValue()

                if isinstance(value_type, renderers.UnreadableValue):
                    vollog.debug(
                        "Couldn't read registry value type, so data is unreadable"
                    )
                    value_data: Union[
                        interfaces.renderers.BaseAbsentValue, bytes
                    ] = renderers.UnreadableValue()
                else:
                    try:
                        value_data = node.decode_data()

                        if isinstance(value_data, int):
                            value_data = format_hints.MultiTypeData(
                                value_data, encoding="utf-8"
                            )
                        elif RegValueTypes(node.Type) == RegValueTypes.REG_BINARY:
                            value_data = format_hints.MultiTypeData(
                                value_data, show_hex=True
                            )
                        elif RegValueTypes(node.Type) == RegValueTypes.REG_MULTI_SZ:
                            value_data = format_hints.MultiTypeData(
                                value_data, encoding="utf-16-le", split_nulls=True
                            )
                        else:
                            value_data = format_hints.MultiTypeData(
                                value_data, encoding="utf-16-le"
                            )
                    except (
                        ValueError,
                        exceptions.InvalidAddressException,
                        RegistryFormatException,
                    ) as excp:
                        vollog.debug(excp)
                        value_data = renderers.UnreadableValue()

                result = (
                    depth,
                    (
                        last_write_time,
                        renderers.format_hints.Hex(hive.hive_offset),
                        value_type,
                        key_path,
                        value_node_name,
                        value_data,
                        volatile,
                    ),
                )
                yield result

    def _registry_walker(
        self,
        layer_name: str,
        symbol_table: str,
        hive_offsets: List[int] = None,
        key: str = None,
        recurse: bool = False,
    ):
        for hive in hivelist.HiveList.list_hives(
            self.context,
            self.config_path,
            layer_name=layer_name,
            symbol_table=symbol_table,
            hive_offsets=hive_offsets,
        ):
            try:
                # Walk it
                if key is not None:
                    node_path = hive.get_key(key, return_list=True)
                else:
                    node_path = [hive.get_node(hive.root_cell_offset)]
                for x, y in self._printkey_iterator(hive, node_path, recurse=recurse):
                    yield (x - len(node_path), y)
            except (
                exceptions.InvalidAddressException,
                KeyError,
                RegistryFormatException,
            ) as excp:
                if isinstance(excp, KeyError):
                    vollog.debug(
                        f"Key '{key}' not found in Hive at offset {hex(hive.hive_offset)}."
                    )
                elif isinstance(excp, RegistryFormatException):
                    vollog.debug(excp)
                elif isinstance(excp, exceptions.InvalidAddressException):
                    vollog.debug(
                        f"Invalid address identified in Hive: {hex(excp.invalid_address)}"
                    )
                result = (
                    0,
                    (
                        renderers.UnreadableValue(),
                        format_hints.Hex(hive.hive_offset),
                        "Key",
                        "?\\" + (key or ""),
                        renderers.UnreadableValue(),
                        renderers.UnreadableValue(),
                        renderers.UnreadableValue(),
                    ),
                )
                yield result

    def run(self):
        offset = self.config.get("offset", None)
        kernel = self.context.modules[self.config["kernel"]]

        return TreeGrid(
            columns=[
                ("Last Write Time", datetime.datetime),
                ("Hive Offset", format_hints.Hex),
                ("Type", str),
                ("Key", str),
                ("Name", str),
                ("Data", format_hints.MultiTypeData),
                ("Volatile", bool),
            ],
            generator=self._registry_walker(
                kernel.layer_name,
                kernel.symbol_table_name,
                hive_offsets=None if offset is None else [offset],
                key=self.config.get("key", None),
                recurse=self.config.get("recurse", None),
            ),
        )
