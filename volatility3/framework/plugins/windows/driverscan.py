# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

from typing import Iterable, Optional, Tuple

from volatility3.framework import renderers, interfaces, exceptions
from volatility3.framework.configuration import requirements
from volatility3.framework.renderers import format_hints
from volatility3.plugins.windows import poolscanner


class DriverScan(interfaces.plugins.PluginInterface):
    """Scans for drivers present in a particular windows memory image."""

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
            requirements.PluginRequirement(
                name="poolscanner", plugin=poolscanner.PoolScanner, version=(1, 0, 0)
            ),
        ]

    @classmethod
    def scan_drivers(
        cls,
        context: interfaces.context.ContextInterface,
        layer_name: str,
        symbol_table: str,
    ) -> Iterable[interfaces.objects.ObjectInterface]:
        """Scans for drivers using the poolscanner module and constraints.

        Args:
            context: The context to retrieve required elements (layers, symbol tables) from
            layer_name: The name of the layer on which to operate
            symbol_table: The name of the table containing the kernel symbols

        Returns:
            A list of Driver objects as found from the `layer_name` layer based on Driver pool signatures
        """

        constraints = poolscanner.PoolScanner.builtin_constraints(
            symbol_table, [b"Dri\xf6", b"Driv"]
        )

        layer = context.layers[layer_name]
        module = context.module(symbol_table, layer_name, 0)
        driver_start_offset = module.get_type("_DRIVER_OBJECT").relative_child_offset(
            "DriverStart"
        )

        for result in poolscanner.PoolScanner.generate_pool_scan(
            context, layer_name, symbol_table, constraints
        ):
            _constraint, mem_object, _header = result

            # *Many* _DRIVER_OBJECT instances were found at the end of a page
            # leading to member access causing backtraces across several plugins
            # when members were accessed as the next page was paged out.
            # `DriverStart` is the first member from the beginning of the structure
            #  of interest to plugins, so if it is not accessible then this instance
            # is not useful or usable during analysis
            # 8 covers this value 32 and 64 bit systems
            if layer.is_valid(mem_object.vol.offset + driver_start_offset, 8):

                # Many/most rootkits zero out their DriverStart member for anti-forensics
                # so we accept a driver start that is either 0 or is mapped in kernel memory (the current layer)
                if mem_object.DriverStart == 0 or layer.is_valid(
                    mem_object.DriverStart, 8
                ):
                    yield mem_object

    @classmethod
    def get_names_for_driver(
        cls, driver
    ) -> Tuple[Optional[str], Optional[str], Optional[str]]:
        """
        Convenience method for getting the commonly used
        names associated with a driver

        Args:
            driver: A Driver object

        Returns:
            A tuple of strings of (driver name, service key, driver alt. name)
        """
        try:
            driver_name = driver.get_driver_name()
        except (ValueError, exceptions.InvalidAddressException):
            driver_name = None

        try:
            service_key = driver.DriverExtension.ServiceKeyName.String
        except exceptions.InvalidAddressException:
            service_key = None

        try:
            name = driver.DriverName.String
        except exceptions.InvalidAddressException:
            name = None

        return driver_name, service_key, name

    def _generator(self):
        kernel = self.context.modules[self.config["kernel"]]

        for driver in self.scan_drivers(
            self.context, kernel.layer_name, kernel.symbol_table_name
        ):
            driver_name, service_key, name = self.get_names_for_driver(driver)

            # Prior to #1481, this plugin reported dozens to hundreds of junk drivers per sample
            if (
                driver.DriverStart == 0
                and not driver_name
                and not service_key
                and not name
            ):
                continue

            yield (
                0,
                (
                    format_hints.Hex(driver.vol.offset),
                    format_hints.Hex(driver.DriverStart),
                    format_hints.Hex(driver.DriverSize),
                    service_key or renderers.NotAvailableValue(),
                    driver_name or renderers.NotAvailableValue(),
                    name or renderers.NotAvailableValue(),
                ),
            )

    def run(self):
        return renderers.TreeGrid(
            [
                ("Offset", format_hints.Hex),
                ("Start", format_hints.Hex),
                ("Size", format_hints.Hex),
                ("Service Key", str),
                ("Driver Name", str),
                ("Name", str),
            ],
            self._generator(),
        )
