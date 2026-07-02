# This file is Copyright 2025 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
import logging
import os
from typing import List, Tuple, Iterator, Generator, Dict

from volatility3.framework import interfaces, renderers, symbols, exceptions
from volatility3.framework.configuration import requirements
from volatility3.framework.renderers import format_hints
from volatility3.framework.symbols import intermed
from volatility3.framework.symbols.windows import versions
from volatility3.plugins.windows import poolscanner, modules
from volatility3.framework.symbols.windows.extensions import gui

vollog = logging.getLogger(__name__)


class WindowStations(interfaces.plugins.PluginInterface):
    """Scans for top level Windows Stations"""

    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 0)

    # These checks must be completed from newest -> oldest OS version.
    _win_version_file_map: List[Tuple[versions.OsDistinguisher, str]] = [
        (versions.is_win10_19577_or_later, "gui-win10-19577-x64"),
        (versions.is_win10_19041_or_later, "gui-win10-19041-x64"),
        (versions.is_win10_18362_or_later, "gui-win10-18362-x64"),
        (versions.is_win10_17763_or_later, "gui-win10-17763-x64"),
        (versions.is_win10_17134_or_later, "gui-win10-17134-x64"),
        (versions.is_win10_16299_or_later, "gui-win10-16299-x64"),
        (versions.is_win10_15063_or_later, "gui-win10-15063-x64"),
        (versions.is_win10_10586_or_later, "gui-win10-10586-x64"),
        (versions.is_windows_8_or_later, "gui-win8-x64"),
        (versions.is_windows_7_sp1, "gui-win7sp1-x64"),
        (versions.is_windows_7_sp0, "gui-win7sp0-x64"),
    ]

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        # Since we're calling the plugin, make sure we have the plugin's requirements
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Windows kernel",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.VersionRequirement(
                name="poolscanner", component=poolscanner.PoolScanner, version=(3, 0, 0)
            ),
            requirements.VersionRequirement(
                name="modules", component=modules.Modules, version=(3, 0, 0)
            ),
            requirements.VersionRequirement(
                name="GUIExtensions", component=gui.GUIExtensions, version=(1, 0, 0)
            ),
        ]

    @staticmethod
    def create_gui_table(
        context: interfaces.context.ContextInterface,
        symbol_table: str,
        config_path: str,
    ) -> str:
        """Creates a symbol table for windows GUI types

        Args:
            context: The context to retrieve required elements (layers, symbol tables) from
            symbol_table: The name of an existing symbol table containing the kernel symbols
            config_path: The configuration path within the context of the symbol table to create

        Returns:
            The name of the constructed GUI table
        """

        if not symbols.symbol_table_is_64bit(
            context=context, symbol_table_name=symbol_table
        ):
            raise NotImplementedError(
                "This plugin only supports x64 versions of Windows"
            )

        table_mapping = {"nt_symbols": symbol_table}

        try:
            symbol_filename = next(
                filename
                for version_check, filename in WindowStations._win_version_file_map
                if version_check(context=context, symbol_table=symbol_table)
            )
        except StopIteration:
            raise NotImplementedError("This version of Windows is not supported!")

        vollog.debug(f"Using GUI table {symbol_filename}")

        return intermed.IntermediateSymbolTable.create(
            context=context,
            config_path=config_path,
            sub_path=os.path.join("windows", "gui"),
            filename=symbol_filename,
            class_types=gui.GUIExtensions.class_types,
            table_mapping=table_mapping,
        )

    @classmethod
    def get_session_map(
        cls,
        context: interfaces.context.ContextInterface,
        module_name: str,
        gui_table_name: str,
    ) -> Dict[int, interfaces.context.ModuleInterface]:
        """
        Walks each session layer and returns a dictionary that
        maps session identifiers to a module in the session's layer
        """
        session_map = modules.Modules.get_session_layers_map(context, module_name)

        for session_id, session_layer in session_map.items():
            session_module = context.module(
                gui_table_name,
                layer_name=session_layer,
                offset=context.modules[module_name].offset,
            )
            session_map[session_id] = session_module

        return session_map

    @classmethod
    def scan_gui_object(
        cls,
        context: interfaces.context.ContextInterface,
        config_path: str,
        kernel_module_name: str,
        object_tag: bytes,
        object_type: str,
    ) -> Generator[interfaces.objects.ObjectInterface, None, None]:
        """
        An API that generically scans for GUI (win32*.sys) objects allocated in the pools (which is nearly all of them)

        This function scans within the kernel space for the tags and then uses `get_session_map` to instantiate objects
        in their correct session address space.

        Args:
            context:
            config_path:
            kernel_module_name:
            object_tag: The 4 byte pool header tag to search for
            object_type: The data structure of the GUI object within the pool
        """

        kernel = context.modules[kernel_module_name]

        gui_table_name = cls.create_gui_table(
            context, kernel.symbol_table_name, config_path
        )

        constraints = poolscanner.PoolScanner.gui_poolscanner_constraints(
            gui_table_name, [object_tag]
        )

        session_map = cls.get_session_map(context, kernel_module_name, gui_table_name)

        for result in poolscanner.PoolScanner.generate_pool_scan_extended(
            context=context,
            kernel_module_name=kernel_module_name,
            object_symbol_table_name=gui_table_name,
            constraints=constraints,
        ):
            _constraint, mem_object, _header = result

            # enforce that objects are in a valid session
            # this prevents smear and also ensures future pointer
            # dereferences are performed in the correct address space (layer)
            try:
                session_id = mem_object.get_session_id()
            except exceptions.InvalidAddressException:
                continue

            if session_id is not None:
                session_module = session_map.get(session_id, None)
                if session_module:
                    # create the object its own address space (per-session)
                    yield session_module.object(
                        object_type=object_type,
                        offset=mem_object.vol.offset,
                        absolute=True,
                    )

    @classmethod
    def scan_window_stations(
        cls,
        context: interfaces.context.ContextInterface,
        config_path: str,
        kernel_module_name: str,
    ) -> Iterator[Tuple["gui.tagWINDOWSTATION", str, int]]:
        """
        Scans for window stations through `scan_gui_object`
        Yields each window station along with its name and session_id
        """

        seen = set()

        kernel = context.modules[kernel_module_name]

        for scanned_winsta in cls.scan_gui_object(
            context, config_path, kernel_module_name, b"Wind", "tagWINDOWSTATION"
        ):
            # walk the list of each station found through scanning
            for winsta in scanned_winsta.traverse():
                if winsta.vol.offset in seen:
                    continue
                seen.add(winsta.vol.offset)

                # stations need to have a name and be in a session
                name, session_id = winsta.get_info(kernel.symbol_table_name)
                if name and session_id is not None:
                    yield winsta, name, session_id

    def _generator(self):
        """
        A wrapper around `scan_window_stations`
        """
        for winsta, name, session_id in self.scan_window_stations(
            self.context, self.config_path, self.config["kernel"]
        ):
            yield (
                0,
                (
                    format_hints.Hex(winsta.vol.offset),
                    name,
                    session_id,
                ),
            )

    # Volatility 2 reported whether the station is interactive or not, but I could not determine if its algorithm
    # is currently valid. I also did not see where the old code paths still checked the same bit mask
    def run(self):
        return renderers.TreeGrid(
            [
                ("Offset", format_hints.Hex),
                ("Name", str),
                ("SessionId", int),
            ],
            self._generator(),
        )
