# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
import logging
from typing import Generator, Iterable, List, Optional, Dict, Tuple

from volatility3.framework import symbols, constants, exceptions, interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.renderers import format_hints
from volatility3.framework.symbols import intermed
from volatility3.framework.symbols.windows.extensions import pe
from volatility3.plugins.windows import pedump, pslist

vollog = logging.getLogger(__name__)


class Modules(interfaces.plugins.PluginInterface):
    """Lists the loaded kernel modules."""

    _required_framework_version = (2, 0, 0)

    # 3.0.0 - changed signature of get_session_layers, added get_session_layers_map
    _version = (3, 0, 0)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._enumeration_method = self.list_modules

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Windows kernel",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.VersionRequirement(
                name="pslist", component=pslist.PsList, version=(3, 0, 0)
            ),
            requirements.VersionRequirement(
                name="pedump", component=pedump.PEDump, version=(2, 0, 0)
            ),
            requirements.BooleanRequirement(
                name="dump",
                description="Extract listed modules",
                default=False,
                optional=True,
            ),
            requirements.IntRequirement(
                name="base",
                description="Extract a single module with BASE address",
                optional=True,
            ),
            requirements.StringRequirement(
                name="name",
                description="module name/sub string",
                optional=True,
                default=None,
            ),
        ]

    def dump_module(self, session_layers, pe_table_name, mod):
        session_layer_name = self.find_session_layer(
            self.context, session_layers, mod.DllBase
        )
        file_output = f"Cannot find a viable session layer for {mod.DllBase:#x}"
        if session_layer_name:
            file_output = pedump.PEDump.dump_ldr_entry(
                self.context,
                pe_table_name,
                mod,
                self.open,
                layer_name=session_layer_name,
            )
            if not file_output:
                file_output = "Error outputting file"

        return file_output

    def _generator(self):
        pe_table_name = None
        session_layers = None

        if self.config["dump"]:
            pe_table_name = intermed.IntermediateSymbolTable.create(
                self.context,
                self.config_path,
                "windows",
                "pe",
                class_types=pe.class_types,
            )

            session_layers = list(
                self.get_session_layers(
                    context=self.context,
                    kernel_module_name=self.config["kernel"],
                )
            )

        for mod in self._enumeration_method(
            self.context, kernel_module_name=self.config["kernel"]
        ):
            if self.config["base"] and self.config["base"] != mod.DllBase:
                continue

            try:
                BaseDllName = mod.BaseDllName.get_string()
                if self.config["name"] and self.config["name"] not in BaseDllName:
                    continue
            except exceptions.InvalidAddressException:
                BaseDllName = interfaces.renderers.BaseAbsentValue()

            try:
                FullDllName = mod.FullDllName.get_string()
            except exceptions.InvalidAddressException:
                FullDllName = interfaces.renderers.BaseAbsentValue()

            file_output = "Disabled"
            if self.config["dump"]:
                file_output = self.dump_module(session_layers, pe_table_name, mod)

            yield 0, (
                format_hints.Hex(mod.vol.offset),
                format_hints.Hex(mod.DllBase),
                format_hints.Hex(mod.SizeOfImage),
                BaseDllName,
                FullDllName,
                file_output,
            )

    @classmethod
    def get_kernel_space_start(cls, context, module_name: str) -> int:
        """
        Returns the starting address of the kernel address space

        This method allows plugins that analyze kernel data structures to quickly detect
        smeared or otherwise invalid data as many pointers must point into the kernel or
        access during runtime would crash the system
        """
        module = context.modules[module_name]

        # default is used if/when MmSystemRangeStart is paged out
        if symbols.symbol_table_is_64bit(
            context=context, symbol_table_name=module.symbol_table_name
        ):
            object_type = "unsigned long long"
            default_start = 0xFFFF800000000000
        else:
            object_type = "unsigned long"
            default_start = 0x80000000

        range_start_offset = module.get_symbol("MmSystemRangeStart").address

        try:
            kernel_space_start = module.object(
                object_type=object_type, offset=range_start_offset
            )
        except exceptions.InvalidAddressException:
            vollog.debug(
                f"Unable to read MmSystemRangeStart. Defaulting to {default_start:#x} for the kernel space start."
            )
            kernel_space_start = default_start

        layer = context.layers[module.layer_name]

        return kernel_space_start & layer.address_mask

    @classmethod
    def _do_get_session_layers(
        cls,
        context: interfaces.context.ContextInterface,
        kernel_module_name: str,
        pids: Optional[List[int]] = None,
    ) -> Generator[Tuple[int, str], None, None]:
        """Build a cache of possible virtual layers, in priority starting with
        the primary/kernel layer. Then keep one layer per session by cycling
        through the process list.

        Args:
            context: The context to retrieve required elements (layers, symbol tables) from
            kernel_module_name: The name of the module for the kernel
            pids: A list of process identifiers to include exclusively or None for no filter

        Returns:
            A generator of session layer names
        """
        seen_ids: List[interfaces.objects.ObjectInterface] = []
        filter_func = pslist.PsList.create_pid_filter(pids or [])

        kernel = context.modules[kernel_module_name]

        for proc in pslist.PsList.list_processes(
            context=context,
            kernel_module_name=kernel_module_name,
            filter_func=filter_func,
        ):
            proc_id = "Unknown"
            try:
                proc_id = proc.UniqueProcessId
                proc_layer_name = proc.add_process_layer()

                # create the session space object in the process' own layer.
                # not all processes have a valid session pointer.
                try:
                    session_space = context.object(
                        kernel.symbol_table_name + constants.BANG + "_MM_SESSION_SPACE",
                        layer_name=kernel.layer_name,
                        offset=proc.Session,
                    )
                    session_id = session_space.SessionId

                except exceptions.SymbolError:
                    # In Windows 11 24H2, the _MM_SESSION_SPACE type was
                    # replaced with _PSP_SESSION_SPACE, and the kernel PDB
                    # doesn't contain information about its members (otherwise,
                    # we would just fall back to the new type). However, it
                    # appears to be, for our purposes, functionally identical
                    # to the _MM_SESSION_SPACE. Because _MM_SESSION_SPACE
                    # stores its session ID at offset 8 as an unsigned long, we
                    # create an unsigned long at that offset and use that
                    # instead.
                    session_id = context.object(
                        layer_name=kernel.layer_name,
                        object_type=kernel.symbol_table_name
                        + constants.BANG
                        + "unsigned long",
                        offset=proc.Session + 8,
                    )

                if session_id in seen_ids:
                    continue

            except exceptions.InvalidAddressException:
                vollog.log(
                    constants.LOGLEVEL_VVV,
                    f"Process {proc_id} does not have a valid Session or a layer could not be constructed for it",
                )
                continue

            # save the layer if we haven't seen the session yet
            seen_ids.append(session_id)
            yield session_id, proc_layer_name

    @classmethod
    def get_session_layers(
        cls,
        context: interfaces.context.ContextInterface,
        kernel_module_name: str,
        pids: Optional[List[int]] = None,
    ) -> Generator[str, None, None]:
        """
        Args:
            context: The context to retrieve required elements (layers, symbol tables) from
            kernel_module_name: The name of the module for the kernel
            pids: A list of process identifiers to include exclusively or None for no filter

        Yields the names of the unique memory layers that map sessions
        """
        for _session_id, proc_layer_name in cls._do_get_session_layers(
            context, kernel_module_name, pids
        ):
            yield proc_layer_name

    @classmethod
    def get_session_layers_map(
        cls,
        context: interfaces.context.ContextInterface,
        kernel_module_name: str,
        pids: Optional[List[int]] = None,
    ) -> Dict[int, str]:
        """
        Args:
            context: The context to retrieve required elements (layers, symbol tables) from
            kernel_module_name: The name of the module for the kernel
            pids: A list of process identifiers to include exclusively or None for no filter

        Wraps `_do_get_session_layers` to produce a dictionary where each key is a session_id
        and the value is the name of the layer for that session
        """
        return dict(cls._do_get_session_layers(context, kernel_module_name, pids))

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

    @classmethod
    def list_modules(
        cls,
        context: interfaces.context.ContextInterface,
        kernel_module_name: str,
    ) -> Iterable[interfaces.objects.ObjectInterface]:
        """Lists all the modules in the primary layer.

        Args:
            context: The context to retrieve required elements (layers, symbol tables) from
            kernel_module_name: The name of the module for the kernel
        Returns:
            A list of Modules as retrieved from PsLoadedModuleList
        """

        kernel = context.modules[kernel_module_name]
        if not kernel.offset:
            raise ValueError(
                "Intel layer does not have an associated kernel virtual offset, failing"
            )

        try:
            # use this type if its available (starting with windows 10)
            ldr_entry_type = kernel.get_type("_KLDR_DATA_TABLE_ENTRY")
        except exceptions.SymbolError:
            ldr_entry_type = kernel.get_type("_LDR_DATA_TABLE_ENTRY")

        type_name = ldr_entry_type.type_name.split(constants.BANG)[1]

        list_head = kernel.get_symbol("PsLoadedModuleList").address
        list_entry = kernel.object(object_type="_LIST_ENTRY", offset=list_head)
        reloff = ldr_entry_type.relative_child_offset("InLoadOrderLinks")
        module = kernel.object(
            object_type=type_name, offset=list_entry.vol.offset - reloff, absolute=True
        )

        yield from module.InLoadOrderLinks

    def run(self):
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
