# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

import contextlib
import logging
from typing import Dict, Iterable, List, Optional, Tuple, Union, cast

from volatility3.framework import (
    constants,
    exceptions,
    interfaces,
    objects,
    renderers,
    symbols,
)
from volatility3.framework.configuration import requirements
from volatility3.framework.renderers import format_hints
from volatility3.framework.symbols import intermed
from volatility3.framework.symbols.windows import versions
from volatility3.framework.symbols.windows.extensions import callbacks
from volatility3.plugins.windows import driverirp, handles, poolscanner, ssdt

vollog = logging.getLogger(__name__)


class Callbacks(interfaces.plugins.PluginInterface):
    """Lists kernel callbacks and notification routines."""

    _required_framework_version = (2, 0, 0)
    _version = (2, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Windows kernel",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.PluginRequirement(
                name="ssdt", plugin=ssdt.SSDT, version=(1, 0, 0)
            ),
            requirements.PluginRequirement(
                name="poolscanner", plugin=poolscanner.PoolScanner, version=(1, 0, 0)
            ),
            requirements.PluginRequirement(
                name="driverirp", plugin=driverirp.DriverIrp, version=(1, 0, 0)
            ),
            requirements.PluginRequirement(
                name="handles", plugin=handles.Handles, version=(1, 0, 0)
            ),
        ]

    @classmethod
    def create_callback_scan_constraints(
        cls,
        context: interfaces.context.ContextInterface,
        symbol_table: str,
        is_vista_or_above: bool,
    ) -> List[poolscanner.PoolConstraint]:
        """Creates a list of Pool Tag Constraints for callback objects.

        Args:
            context: The context to retrieve required elements (layers, symbol tables) from
            symbol_table: The name of an existing symbol table containing the symbols / types
            is_vista_or_above: A boolean indicating whether the OS version is Vista or newer.

        Returns:
            The list containing the built constraints.
        """
        constraints = cls._create_default_scan_constraints(context, symbol_table)
        if is_vista_or_above:
            constraints += cls._create_scan_constraints_vista_and_above(symbol_table)
        return constraints

    @staticmethod
    def _create_default_scan_constraints(
        context: interfaces.context.ContextInterface, symbol_table: str
    ) -> List[poolscanner.PoolConstraint]:

        shutdown_packet_size = context.symbol_space.get_type(
            symbol_table + constants.BANG + "_SHUTDOWN_PACKET"
        ).size
        generic_callback_size = context.symbol_space.get_type(
            symbol_table + constants.BANG + "_GENERIC_CALLBACK"
        ).size
        notification_packet_size = context.symbol_space.get_type(
            symbol_table + constants.BANG + "_NOTIFICATION_PACKET"
        ).size

        return [
            poolscanner.PoolConstraint(
                b"IoFs",
                type_name=symbol_table + constants.BANG + "_NOTIFICATION_PACKET",
                size=(notification_packet_size, None),
                page_type=poolscanner.PoolType.NONPAGED
                | poolscanner.PoolType.PAGED
                | poolscanner.PoolType.FREE,
            ),
            poolscanner.PoolConstraint(
                b"IoSh",
                type_name=symbol_table + constants.BANG + "_SHUTDOWN_PACKET",
                size=(shutdown_packet_size, None),
                page_type=poolscanner.PoolType.NONPAGED
                | poolscanner.PoolType.PAGED
                | poolscanner.PoolType.FREE,
                index=(0, 0),
            ),
            poolscanner.PoolConstraint(
                b"Cbrb",
                type_name=symbol_table + constants.BANG + "_GENERIC_CALLBACK",
                size=(generic_callback_size, None),
                page_type=poolscanner.PoolType.NONPAGED
                | poolscanner.PoolType.PAGED
                | poolscanner.PoolType.FREE,
            ),
        ]

    @staticmethod
    def _create_scan_constraints_vista_and_above(
        symbol_table: str,
    ) -> List[poolscanner.PoolConstraint]:
        """Creates a list of Pool Tag Constraints for callback objects.

        Args:
            context: The context to retrieve required elements (layers, symbol tables) from
            symbol_table: The name of an existing symbol table containing the symbols / types

        Returns:
            The list containing the built constraints.
        """

        return [
            poolscanner.PoolConstraint(
                b"DbCb",
                type_name=symbol_table + constants.BANG + "_DBGPRINT_CALLBACK",
                size=(0x20, 0x40),
                page_type=poolscanner.PoolType.NONPAGED
                | poolscanner.PoolType.PAGED
                | poolscanner.PoolType.FREE,
            ),
            poolscanner.PoolConstraint(
                b"Pnp9",
                type_name=symbol_table + constants.BANG + "_NOTIFY_ENTRY_HEADER",
                size=(0x30, None),
                page_type=poolscanner.PoolType.NONPAGED
                | poolscanner.PoolType.PAGED
                | poolscanner.PoolType.FREE,
                index=(1, 1),
            ),
            poolscanner.PoolConstraint(
                b"PnpD",
                type_name=symbol_table + constants.BANG + "_NOTIFY_ENTRY_HEADER",
                size=(0x40, None),
                page_type=poolscanner.PoolType.NONPAGED
                | poolscanner.PoolType.PAGED
                | poolscanner.PoolType.FREE,
                index=(1, 1),
            ),
            poolscanner.PoolConstraint(
                b"PnpC",
                type_name=symbol_table + constants.BANG + "_NOTIFY_ENTRY_HEADER",
                size=(0x38, None),
                page_type=poolscanner.PoolType.NONPAGED
                | poolscanner.PoolType.PAGED
                | poolscanner.PoolType.FREE,
                index=(1, 1),
            ),
        ]

    @classmethod
    def create_callback_symbol_table(
        cls,
        context: interfaces.context.ContextInterface,
        nt_symbol_table: str,
        config_path: str,
    ) -> str:
        """Creates a symbol table for kernel callback objects.

        Args:
            context: The context to retrieve required elements (layers, symbol tables) from
            nt_symbol_table: The name of the table containing the kernel symbols
            config_path: The config path where to find symbol files

        Returns:
            The name of the constructed symbol table
        """
        native_types = context.symbol_space[nt_symbol_table].natives
        is_64bit = symbols.symbol_table_is_64bit(context, nt_symbol_table)
        table_mapping = {"nt_symbols": nt_symbol_table}

        if is_64bit:
            symbol_filename = "callbacks-x64"
        else:
            symbol_filename = "callbacks-x86"

        return intermed.IntermediateSymbolTable.create(
            context,
            config_path,
            "windows",
            symbol_filename,
            class_types=callbacks.class_types_x86 if not is_64bit else None,
            native_types=native_types,
            table_mapping=table_mapping,
        )

    @classmethod
    def scan(
        cls,
        context: interfaces.context.ContextInterface,
        layer_name: str,
        nt_symbol_table: str,
        callback_symbol_table: str,
    ) -> Iterable[
        Tuple[
            Union[str, interfaces.renderers.BaseAbsentValue],
            int,
            Union[str, interfaces.renderers.BaseAbsentValue],
        ]
    ]:
        """Scans for callback objects using the poolscanner module and constraints.

        Args:
            context: The context to retrieve required elements (layers, symbol tables) from
            layer_name: The name of the layer on which to operate
            nt_symbol_table: The name of the table containing the kernel symbols
            callback_symbol_table: The name of the table containing the callback object symbols (_SHUTDOWN_PACKET etc.)

        Returns:
            A list of callback objects found by scanning the `layer_name` layer for callback pool signatures
        """
        is_vista_or_later = versions.is_vista_or_later(
            context=context, symbol_table=nt_symbol_table
        )

        type_map = handles.Handles.get_type_map(context, layer_name, nt_symbol_table)

        constraints = cls.create_callback_scan_constraints(
            context, callback_symbol_table, is_vista_or_later
        )

        for (
            _constraint,
            mem_object,
            _header,
        ) in poolscanner.PoolScanner.generate_pool_scan(
            context, layer_name, nt_symbol_table, constraints
        ):
            try:
                if isinstance(mem_object, callbacks._SHUTDOWN_PACKET):
                    if not mem_object.is_parseable(type_map):
                        continue
                elif hasattr(mem_object, "is_valid"):
                    if not mem_object.is_valid():
                        continue

                yield cls._process_scanned_callback(mem_object, type_map)
            except exceptions.InvalidAddressException:
                continue

    @classmethod
    def _process_scanned_callback(
        cls, memory_object: objects.StructType, type_map: Dict[int, str]
    ) -> Tuple[
        Union[str, interfaces.renderers.BaseAbsentValue],
        int,
        Union[str, interfaces.renderers.BaseAbsentValue],
    ]:
        symbol_table = memory_object.get_symbol_table_name()
        type_name = memory_object.vol.type_name

        if isinstance(memory_object, callbacks._SHUTDOWN_PACKET) or (
            type_name == symbol_table + constants.BANG + "_SHUTDOWN_PACKET"
        ):
            callback_type = "IoRegisterShutdownNotification"

            try:
                driver = memory_object.DeviceObject.DriverObject
                index = driverirp.MAJOR_FUNCTIONS.index("IRP_MJ_SHUTDOWN")
                callback_address = driver.MajorFunction[index]
                details = driver.DriverName.String or renderers.UnparsableValue()
            except exceptions.InvalidAddressException:
                callback_address = memory_object.vol.offset
                details = renderers.NotApplicableValue()

        elif type_name == symbol_table + constants.BANG + "_NOTIFICATION_PACKET":
            callback_type = "IoRegisterFsRegistrationChange"
            callback_address = memory_object.NotificationRoutine
            details = renderers.NotApplicableValue()

        elif type_name == symbol_table + constants.BANG + "_NOTIFY_ENTRY_HEADER":
            driver = (
                memory_object.DriverObject.dereference()
                if memory_object.DriverObject.is_readable()
                else None
            )

            if driver:
                # Instantiate an object header for the driver name
                header = driver.get_object_header()
                try:
                    if header.get_object_type(type_map) == "Driver":
                        # Grab the object name
                        details = header.NameInfo.Name.String
                    else:
                        details = renderers.NotApplicableValue()
                except exceptions.InvalidAddressException:
                    details = renderers.UnreadableValue()
            else:
                details = renderers.UnreadableValue()

            callback_type = (
                memory_object.EventCategory.description
                if memory_object.EventCategory.is_valid_choice
                else renderers.UnparsableValue()
            )

            callback_address = memory_object.CallbackRoutine

        elif type_name == symbol_table + constants.BANG + "_GENERIC_CALLBACK":
            callback_type = "GenericKernelCallback"
            callback_address = memory_object.Callback
            details = renderers.NotApplicableValue()

        elif type_name == symbol_table + constants.BANG + "_DBGPRINT_CALLBACK":
            callback_type = "DbgSetDebugPrintCallback"
            callback_address = memory_object.Function
            details = renderers.NotApplicableValue()

        else:
            raise ValueError(f"Unexpected object type {type_name}")

        return (
            callback_type,
            callback_address,
            (
                details
                if not isinstance(details, interfaces.renderers.BaseAbsentValue)
                else details
            ),
        )

    @classmethod
    def list_notify_routines(
        cls,
        context: interfaces.context.ContextInterface,
        layer_name: str,
        symbol_table: str,
        callback_table_name: str,
    ) -> Iterable[Tuple[str, int, Optional[str]]]:
        """Lists all kernel notification routines.

        Args:
            context: The context to retrieve required elements (layers, symbol tables) from
            layer_name: The name of the layer on which to operate
            symbol_table: The name of the table containing the kernel symbols
            callback_table_name: The name of the table containing the callback symbols

        Yields:
            A name, location and optional detail string
        """

        kvo = context.layers[layer_name].config["kernel_virtual_offset"]
        ntkrnlmp = context.module(symbol_table, layer_name=layer_name, offset=kvo)

        is_vista_or_later = versions.is_vista_or_later(
            context=context, symbol_table=symbol_table
        )
        full_type_name = callback_table_name + constants.BANG + "_GENERIC_CALLBACK"

        symbol_names = [
            ("PspLoadImageNotifyRoutine", False),
            ("PspCreateThreadNotifyRoutine", True),
            ("PspCreateProcessNotifyRoutine", True),
        ]

        for symbol_name, extended_list in symbol_names:
            try:
                symbol_offset = ntkrnlmp.get_symbol(symbol_name).address
            except exceptions.SymbolError:
                vollog.debug(f"Cannot find {symbol_name}")
                continue

            if is_vista_or_later and extended_list:
                count = 64
            else:
                count = 8

            fast_refs = cast(
                List[objects.Pointer],
                ntkrnlmp.object(
                    object_type="array",
                    offset=symbol_offset,
                    subtype=ntkrnlmp.get_type("_EX_FAST_REF"),
                    count=count,
                ),
            )

            for fast_ref in fast_refs:
                try:
                    callback = fast_ref.dereference().cast(full_type_name)
                except exceptions.InvalidAddressException:
                    continue

                if callback.Callback != 0:
                    yield symbol_name, callback.Callback, None

    @classmethod
    def _list_registry_callbacks_legacy(
        cls,
        context: interfaces.context.ContextInterface,
        layer_name: str,
        symbol_table: str,
        callback_table_name: str,
    ) -> Iterable[Tuple[str, int, None]]:
        """
        Lists all registry callbacks from the old format via the CmpCallBackVector.
        """

        kvo = context.layers[layer_name].config["kernel_virtual_offset"]
        ntkrnlmp = context.module(symbol_table, layer_name=layer_name, offset=kvo)
        full_type_name = (
            callback_table_name + constants.BANG + "_EX_CALLBACK_ROUTINE_BLOCK"
        )

        symbol_offset = ntkrnlmp.get_symbol("CmpCallBackVector").address
        symbol_count_offset = ntkrnlmp.get_symbol("CmpCallBackCount").address

        callback_count = ntkrnlmp.object(
            object_type="unsigned int", offset=symbol_count_offset
        )

        if callback_count == 0:
            return None

        fast_refs = cast(
            List[objects.Pointer],
            ntkrnlmp.object(
                object_type="array",
                offset=symbol_offset,
                subtype=ntkrnlmp.get_type("_EX_FAST_REF"),
                count=callback_count,
            ),
        )

        for fast_ref in fast_refs:
            try:
                callback = fast_ref.dereference().cast(full_type_name)
            except exceptions.InvalidAddressException:
                continue

            if callback.Function != 0:
                yield "CmRegisterCallback", callback.Function, None

    @classmethod
    def _list_registry_callbacks_new(
        cls,
        context: interfaces.context.ContextInterface,
        layer_name: str,
        symbol_table: str,
        callback_table_name: str,
    ) -> Iterable[Tuple[str, int, Optional[str]]]:
        """
        Lists all registry callbacks via the CallbackListHead.
        """

        kvo = context.layers[layer_name].config["kernel_virtual_offset"]
        ntkrnlmp = context.module(symbol_table, layer_name=layer_name, offset=kvo)
        full_type_name = callback_table_name + constants.BANG + "_CM_CALLBACK_ENTRY"

        symbol_offset = ntkrnlmp.get_symbol("CallbackListHead").address
        symbol_count_offset = ntkrnlmp.get_symbol("CmpCallBackCount").address

        callback_count = ntkrnlmp.object(
            object_type="unsigned int", offset=symbol_count_offset
        )

        if callback_count == 0:
            return None

        callback_list = ntkrnlmp.object(object_type="_LIST_ENTRY", offset=symbol_offset)
        for callback in callback_list.to_list(full_type_name, "Link"):
            altitude = None
            with contextlib.suppress(exceptions.InvalidAddressException):
                altitude = callback.Altitude.String
            yield "CmRegisterCallbackEx", callback.Function, f"Altitude: {altitude}"

    @classmethod
    def list_registry_callbacks(
        cls,
        context: interfaces.context.ContextInterface,
        layer_name: str,
        symbol_table: str,
        callback_table_name: str,
    ) -> Iterable[Tuple[str, int, Optional[str]]]:
        """Lists all registry callbacks.

        Args:
            context: The context to retrieve required elements (layers, symbol tables) from
            layer_name: The name of the layer on which to operate
            symbol_table: The name of the table containing the kernel symbols
            callback_table_name: The name of the table containing the callback symbols

        Yields:
            A name, location and optional detail string
        """

        kvo = context.layers[layer_name].config["kernel_virtual_offset"]
        ntkrnlmp = context.module(symbol_table, layer_name=layer_name, offset=kvo)

        if ntkrnlmp.has_symbol("CmpCallBackVector") and ntkrnlmp.has_symbol(
            "CmpCallBackCount"
        ):
            yield from cls._list_registry_callbacks_legacy(
                context, layer_name, symbol_table, callback_table_name
            )
        elif ntkrnlmp.has_symbol("CallbackListHead") and ntkrnlmp.has_symbol(
            "CmpCallBackCount"
        ):
            yield from cls._list_registry_callbacks_new(
                context, layer_name, symbol_table, callback_table_name
            )
        else:
            symbols_to_check = [
                "CmpCallBackVector",
                "CmpCallBackCount",
                "CallbackListHead",
            ]
            vollog.debug("Failed to get registry callbacks!")
            for symbol_name in symbols_to_check:
                symbol_status = "does not exist"
                if ntkrnlmp.has_symbol(symbol_name):
                    symbol_status = "exists"
                vollog.debug(f"symbol {symbol_name} {symbol_status}.")

            return None

    @classmethod
    def list_bugcheck_reason_callbacks(
        cls,
        context: interfaces.context.ContextInterface,
        layer_name: str,
        symbol_table: str,
        callback_table_name: str,
    ) -> Iterable[
        Tuple[
            str,
            int,
            interfaces.renderers.BaseAbsentValue,
        ]
    ]:
        """Lists all kernel bugcheck reason callbacks.

        Args:
            context: The context to retrieve required elements (layers, symbol tables) from
            layer_name: The name of the layer on which to operate
            symbol_table: The name of the table containing the kernel symbols
            callback_table_name: The name of the table containing the callback symbols

        Yields:
            A name, location and optional detail string
        """

        kvo = context.layers[layer_name].config["kernel_virtual_offset"]
        ntkrnlmp = context.module(symbol_table, layer_name=layer_name, offset=kvo)

        try:
            list_offset = ntkrnlmp.get_symbol(
                "KeBugCheckReasonCallbackListHead"
            ).address
        except exceptions.SymbolError:
            vollog.debug("Cannot find KeBugCheckReasonCallbackListHead")
            return None

        full_type_name = (
            callback_table_name + constants.BANG + "_KBUGCHECK_REASON_CALLBACK_RECORD"
        )
        callback_record = context.object(
            object_type=full_type_name, offset=kvo + list_offset, layer_name=layer_name
        )

        for callback in callback_record.Entry:
            if not context.layers[layer_name].is_valid(callback.CallbackRoutine, 64):
                continue

            try:
                component: Union[
                    interfaces.renderers.BaseAbsentValue,
                    interfaces.objects.ObjectInterface,
                ] = ntkrnlmp.object(
                    "string",
                    absolute=True,
                    offset=callback.Component,
                    max_length=64,
                    errors="replace",
                )
            except exceptions.InvalidAddressException:
                component = renderers.UnreadableValue()

            yield "KeBugCheckReasonCallbackListHead", callback.CallbackRoutine, component

    @classmethod
    def list_bugcheck_callbacks(
        cls,
        context: interfaces.context.ContextInterface,
        layer_name: str,
        symbol_table: str,
        callback_table_name: str,
    ) -> Iterable[
        Tuple[
            str,
            int,
            Union[interfaces.objects.ObjectInterface, renderers.UnreadableValue],
        ]
    ]:
        """Lists all kernel bugcheck callbacks.

        Args:
            context: The context to retrieve required elements (layers, symbol tables) from
            layer_name: The name of the layer on which to operate
            symbol_table: The name of the table containing the kernel symbols
            callback_table_name: The name of the table containing the callback symbols

        Yields:
            A name, location and optional detail string
        """

        kvo = context.layers[layer_name].config["kernel_virtual_offset"]
        ntkrnlmp = context.module(symbol_table, layer_name=layer_name, offset=kvo)

        try:
            list_offset = ntkrnlmp.get_symbol("KeBugCheckCallbackListHead").address
        except exceptions.SymbolError:
            vollog.debug("Cannot find KeBugCheckCallbackListHead")
            return None

        full_type_name = (
            callback_table_name + constants.BANG + "_KBUGCHECK_CALLBACK_RECORD"
        )
        callback_record = context.object(
            full_type_name, offset=kvo + list_offset, layer_name=layer_name
        )

        for callback in callback_record.Entry:
            if not context.layers[layer_name].is_valid(callback.CallbackRoutine, 64):
                continue

            try:
                component = context.object(
                    symbol_table + constants.BANG + "string",
                    layer_name=layer_name,
                    offset=callback.Component,
                    max_length=64,
                    errors="replace",
                )
            except exceptions.InvalidAddressException:
                component = renderers.UnreadableValue()

            yield "KeBugCheckCallbackListHead", callback.CallbackRoutine, component

    def _generator(self):
        kernel = self.context.modules[self.config["kernel"]]

        callback_symbol_table = self.create_callback_symbol_table(
            self.context, kernel.symbol_table_name, self.config_path
        )

        collection = ssdt.SSDT.build_module_collection(
            self.context, kernel.layer_name, kernel.symbol_table_name
        )

        callback_methods = (
            self.list_notify_routines,
            self.list_bugcheck_callbacks,
            self.list_bugcheck_reason_callbacks,
            self.list_registry_callbacks,
            self.scan,
        )

        for callback_method in callback_methods:
            for callback_type, callback_address, callback_detail in callback_method(
                self.context,
                kernel.layer_name,
                kernel.symbol_table_name,
                callback_symbol_table,
            ):
                if callback_detail is None:
                    detail = renderers.NotApplicableValue()
                else:
                    detail = callback_detail

                module_symbols = list(
                    collection.get_module_symbols_by_absolute_location(callback_address)
                )

                if module_symbols:
                    for module_name, symbol_generator in module_symbols:
                        symbols_found = False

                        # we might have multiple symbols pointing to the same location
                        for symbol in symbol_generator:
                            symbols_found = True
                            yield (
                                0,
                                (
                                    callback_type,
                                    format_hints.Hex(callback_address),
                                    module_name,
                                    symbol.split(constants.BANG)[1],
                                    detail,
                                ),
                            )

                        # no symbols, but we at least can report the module name
                        if not symbols_found:
                            yield (
                                0,
                                (
                                    callback_type,
                                    format_hints.Hex(callback_address),
                                    module_name,
                                    renderers.NotAvailableValue(),
                                    detail,
                                ),
                            )
                else:
                    # no module was found at the absolute location
                    yield (
                        0,
                        (
                            callback_type,
                            format_hints.Hex(callback_address),
                            renderers.NotAvailableValue(),
                            renderers.NotAvailableValue(),
                            detail,
                        ),
                    )

    def run(self):
        return renderers.TreeGrid(
            [
                ("Type", str),
                ("Callback", format_hints.Hex),
                ("Module", str),
                ("Symbol", str),
                ("Detail", str),
            ],
            self._generator(),
        )
