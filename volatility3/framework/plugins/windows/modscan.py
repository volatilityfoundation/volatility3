# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
import logging
from typing import Iterable, List, Generator

from volatility3.framework import renderers, interfaces, exceptions, constants
from volatility3.framework.configuration import requirements
from volatility3.framework.renderers import format_hints
from volatility3.framework.symbols import intermed
from volatility3.framework.symbols.windows.extensions import pe
from volatility3.plugins.windows import poolscanner, dlllist, pslist

vollog = logging.getLogger(__name__)


class ModScan(interfaces.plugins.PluginInterface):
    """Scans for modules present in a particular windows memory image."""

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
                name="poolscanner", component=poolscanner.PoolScanner, version=(1, 0, 0)
            ),
            requirements.VersionRequirement(
                name="pslist", component=pslist.PsList, version=(2, 0, 0)
            ),
            requirements.VersionRequirement(
                name="dlllist", component=dlllist.DllList, version=(2, 0, 0)
            ),
            requirements.BooleanRequirement(
                name="dump",
                description="Extract listed modules",
                default=False,
                optional=True,
            ),
            requirements.IntRequirement(
                name="base",
                description="Extract a single module with BASE address(hex)",
                optional=True,
            ),
        ]

    @classmethod
    def scan_modules(
        cls,
        context: interfaces.context.ContextInterface,
        layer_name: str,
        symbol_table: str,
    ) -> Iterable[interfaces.objects.ObjectInterface]:
        """Scans for modules using the poolscanner module and constraints.

        Args:
            context: The context to retrieve required elements (layers, symbol tables) from
            layer_name: The name of the layer on which to operate
            symbol_table: The name of the table containing the kernel symbols

        Returns:
            A list of Driver objects as found from the `layer_name` layer based on Driver pool signatures
        """

        constraints = poolscanner.PoolScanner.builtin_constraints(
            symbol_table, [b"MmLd"]
        )

        for result in poolscanner.PoolScanner.generate_pool_scan(
            context, layer_name, symbol_table, constraints
        ):
            _constraint, mem_object, _header = result
            yield mem_object

    @classmethod
    def get_session_layers(
        cls,
        context: interfaces.context.ContextInterface,
        layer_name: str,
        symbol_table: str,
        pids: List[int] = None,
    ) -> Generator[str, None, None]:
        """Build a cache of possible virtual layers, in priority starting with
        the primary/kernel layer. Then keep one layer per session by cycling
        through the process list.

        Args:
            context: The context to retrieve required elements (layers, symbol tables) from
            layer_name: The name of the layer on which to operate
            symbol_table: The name of the table containing the kernel symbols
            pids: A list of process identifiers to include exclusively or None for no filter

        Returns:
            A list of session layer names
        """
        seen_ids: List[interfaces.objects.ObjectInterface] = []
        filter_func = pslist.PsList.create_pid_filter(pids or [])

        for proc in pslist.PsList.list_processes(
            context=context,
            layer_name=layer_name,
            symbol_table=symbol_table,
            filter_func=filter_func,
        ):
            proc_id = "Unknown"
            try:
                proc_id = proc.UniqueProcessId
                proc_layer_name = proc.add_process_layer()

                # create the session space object in the process' own layer.
                # not all processes have a valid session pointer.
                session_space = context.object(
                    symbol_table + constants.BANG + "_MM_SESSION_SPACE",
                    layer_name=layer_name,
                    offset=proc.Session,
                )

                if session_space.SessionId in seen_ids:
                    continue

            except exceptions.InvalidAddressException:
                vollog.log(
                    constants.LOGLEVEL_VVV,
                    "Process {} does not have a valid Session or a layer could not be constructed for it".format(
                        proc_id
                    ),
                )
                continue

            # save the layer if we haven't seen the session yet
            seen_ids.append(session_space.SessionId)
            yield proc_layer_name

    @classmethod
    def find_session_layer(
        cls,
        context: interfaces.context.ContextInterface,
        session_layers: Iterable[str],
        base_address: int,
    ):
        """Given a base address and a list of layer names, find a layer that
        can access the specified address.

        Args:
            context: The context to retrieve required elements (layers, symbol tables) from
            layer_name: The name of the layer on which to operate
            symbol_table: The name of the table containing the kernel symbols
            session_layers: A list of session layer names
            base_address: The base address to identify the layers that can access it

        Returns:
            Layer name or None if no layers that contain the base address can be found
        """

        for layer_name in session_layers:
            if context.layers[layer_name].is_valid(base_address):
                return layer_name

        return None

    def _generator(self):
        kernel = self.context.modules[self.config["kernel"]]

        session_layers = list(
            self.get_session_layers(
                self.context, kernel.layer_name, kernel.symbol_table_name
            )
        )
        pe_table_name = intermed.IntermediateSymbolTable.create(
            self.context, self.config_path, "windows", "pe", class_types=pe.class_types
        )

        for mod in self.scan_modules(
            self.context, kernel.layer_name, kernel.symbol_table_name
        ):
            try:
                BaseDllName = mod.BaseDllName.get_string()
            except exceptions.InvalidAddressException:
                BaseDllName = ""

            try:
                FullDllName = mod.FullDllName.get_string()
            except exceptions.InvalidAddressException:
                FullDllName = ""

            file_output = "Disabled"
            if self.config["dump"] or (self.config["base"] and self.config["base"] == mod.DllBase):
                session_layer_name = self.find_session_layer(
                    self.context, session_layers, mod.DllBase
                )
                file_output = f"Cannot find a viable session layer for {mod.DllBase:#x}"
                if session_layer_name:
                    file_handle = dlllist.DllList.dump_pe(
                        self.context,
                        pe_table_name,
                        mod,
                        self.open,
                        layer_name=session_layer_name,
                    )
                    file_output = "Error outputting file"
                    if file_handle:
                        file_output = file_handle.preferred_filename

            yield (
                0,
                (
                    format_hints.Hex(mod.vol.offset),
                    format_hints.Hex(mod.DllBase),
                    format_hints.Hex(mod.SizeOfImage),
                    BaseDllName,
                    FullDllName,
                    file_output,
                ),
            )

    def run(self):
        if self.config["dump"] and self.config["base"]:
            raise ValueError("--dump cannot be used with --base")

        return renderers.TreeGrid(
            [
                ("Offset", format_hints.Hex),
                ("Base", format_hints.Hex),
                ("Size", format_hints.Hex),
                ("Name", str),
                ("Path", str),
                ("File output", str),
            ],
            self._generator(),
        )
