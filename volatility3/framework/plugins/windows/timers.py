# This file is Copyright 2024 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

import logging

from typing import Iterator, List, Tuple, Iterable

from volatility3.framework import (
    exceptions,
    layers,
    renderers,
    interfaces,
    constants,
    symbols,
)
from volatility3.framework.configuration import requirements
from volatility3.framework.objects import utility
from volatility3.framework.renderers import format_hints
from volatility3.framework.symbols.windows import versions
from volatility3.plugins.windows import ssdt

vollog = logging.getLogger(__name__)


class Timers(interfaces.plugins.PluginInterface):
    """Print kernel timers and associated module DPCs"""

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
                name="ssdt", plugin=ssdt.SSDT, version=(1, 0, 0)
            ),
        ]

    @classmethod
    def get_kernel_module(
        cls,
        context: interfaces.context.ContextInterface,
        layer_name: str,
        symbol_table: str,
    ):
        """Returns the kernel module based on the layer and symbol_table"""
        virtual_layer = context.layers[layer_name]
        if not isinstance(virtual_layer, layers.intel.Intel):
            raise TypeError("Virtual Layer is not an intel layer")

        kvo = virtual_layer.config["kernel_virtual_offset"]

        ntkrnlmp = context.module(symbol_table, layer_name=layer_name, offset=kvo)
        return ntkrnlmp

    @classmethod
    def get_kpcrs(
        cls,
        context: interfaces.context.ContextInterface,
        layer_name: str,
        symbol_table: str,
    ) -> interfaces.objects.ObjectInterface:
        """Returns the KPCR structure for each processor

        Args:
            context: The context to retrieve required elements (layers, symbol tables) from
            symbol_table: The name of an existing symbol table containing the kernel symbols
            config_path: The configuration path within the context of the symbol table to create

        Returns:
            The _KPCR structure for each processor
        """

        ntkrnlmp = cls.get_kernel_module(context, layer_name, symbol_table)
        cpu_count_offset = ntkrnlmp.get_symbol("KeNumberProcessors").address
        cpu_count = ntkrnlmp.object(
            object_type="unsigned int", layer_name=layer_name, offset=cpu_count_offset
        )
        processor_block = ntkrnlmp.object(
            object_type="pointer",
            layer_name=layer_name,
            offset=ntkrnlmp.get_symbol("KiProcessorBlock").address,
        )
        processor_pointers = utility.array_of_pointers(
            context=context,
            array=processor_block,
            count=cpu_count,
            subtype=symbol_table + constants.BANG + "_KPRCB",
        )
        for pointer in processor_pointers:
            kprcb = pointer.dereference()
            reloff = ntkrnlmp.get_type("_KPCR").relative_child_offset("Prcb")
            kpcr = context.object(
                symbol_table + constants.BANG + "_KPCR",
                offset=kprcb.vol.offset - reloff,
                layer_name=layer_name,
            )
            yield kpcr

    @classmethod
    def list_timers(
        cls,
        context: interfaces.context.ContextInterface,
        layer_name: str,
        symbol_table: str,
    ) -> Iterable[Tuple[str, int, str]]:
        """Lists all kernel timers.

        Args:
            context: The context to retrieve required elements (layers, symbol tables) from
            layer_name: The name of the layer on which to operate
            symbol_table: The name of the table containing the kernel symbols

        Yields:
            A _KTIMER entry
        """
        ntkrnlmp = cls.get_kernel_module(context, layer_name, symbol_table)

        if versions.is_windows_7(
            context=context, symbol_table=symbol_table
        ) or versions.is_windows_8_or_later(context=context, symbol_table=symbol_table):
            # Starting with Windows 7, there is no more KiTimerTableListHead. The list is
            # at _KPCR.PrcbData.TimerTable.TimerEntries
            # See http://pastebin.com/FiRsGW3f
            for kpcr in cls.get_kpcrs(context, layer_name, symbol_table):
                if hasattr(kpcr.Prcb.TimerTable, "TableState"):
                    for timer_entries in kpcr.Prcb.TimerTable.TimerEntries:
                        for timer_entry in timer_entries:
                            for timer in timer_entry.Entry.to_list(
                                symbol_table + constants.BANG + "_KTIMER",
                                "TimerListEntry",
                            ):
                                yield timer

                else:
                    for timer_entries in kpcr.Prcb.TimerTable.TimerEntries:
                        for timer in timer_entries.Entry.to_list(
                            symbol_table + constants.BANG + "_KTIMER",
                            "TimerListEntry",
                        ):
                            yield timer

        elif versions.is_xp_or_2003(
            context=context, symbol_table=symbol_table
        ) or versions.is_vista_or_later(context=context, symbol_table=symbol_table):
            is_64bit = symbols.symbol_table_is_64bit(context, symbol_table)
            if is_64bit or versions.is_vista_or_later(
                context=context, symbol_table=symbol_table
            ):
                # On XP x64, Windows 2003 SP1-SP2, and Vista SP0-SP2, KiTimerTableListHead
                # is an array of 512 _KTIMER_TABLE_ENTRY structs.
                array_size = 512
            else:
                # On XP SP0-SP3 x86 and Windows 2003 SP0, KiTimerTableListHead
                # is an array of 256 _LIST_ENTRY for _KTIMERs.
                array_size = 256

            timer_table_list_head = ntkrnlmp.object(
                object_type="array",
                offset=ntkrnlmp.get_symbol("KiTimerTableListHead").address,
                subtype=ntkrnlmp.get_type("_LIST_ENTRY"),
                count=array_size,
            )
            for table in timer_table_list_head:
                for timer in table.to_list(
                    symbol_table + constants.BANG + "_KTIMER",
                    "TimerListEntry",
                ):
                    yield timer

        else:
            raise NotImplementedError("This version of Windows is not supported!")

    def _generator(self) -> Iterator[Tuple]:
        kernel = self.context.modules[self.config["kernel"]]
        layer_name = kernel.layer_name
        symbol_table = kernel.symbol_table_name

        collection = ssdt.SSDT.build_module_collection(
            self.context, kernel.layer_name, kernel.symbol_table_name
        )

        for timer in self.list_timers(self.context, layer_name, symbol_table):
            if not timer.valid_type():
                continue
            try:
                dpc = timer.get_dpc()
                if dpc == 0:
                    continue
                if dpc.DeferredRoutine == 0:
                    continue
                deferred_routine = dpc.DeferredRoutine
            except Exception as e:
                continue

            module_symbols = list(
                collection.get_module_symbols_by_absolute_location(deferred_routine)
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
                                format_hints.Hex(timer.vol.offset),
                                timer.get_due_time(),
                                timer.Period,
                                timer.get_signaled(),
                                format_hints.Hex(deferred_routine),
                                module_name,
                                symbol.split(constants.BANG)[1],
                            ),
                        )

                    # no symbols, but we at least can report the module name
                    if not symbols_found:
                        yield (
                            0,
                            (
                                format_hints.Hex(timer.vol.offset),
                                timer.get_due_time(),
                                timer.Period,
                                timer.get_signaled(),
                                format_hints.Hex(deferred_routine),
                                module_name,
                                renderers.NotAvailableValue(),
                            ),
                        )
            else:
                # no module was found at the absolute location
                yield (
                    0,
                    (
                        format_hints.Hex(timer.vol.offset),
                        timer.get_due_time(),
                        timer.Period,
                        timer.get_signaled(),
                        format_hints.Hex(deferred_routine),
                        renderers.NotAvailableValue(),
                        renderers.NotAvailableValue(),
                    ),
                )

    def run(self):
        return renderers.TreeGrid(
            [
                ("Offset", format_hints.Hex),
                ("DueTime", str),
                ("Period(ms)", int),
                ("Signaled", str),
                ("Routine", format_hints.Hex),
                ("Module", str),
                ("Symbol", str),
            ],
            self._generator(),
        )
