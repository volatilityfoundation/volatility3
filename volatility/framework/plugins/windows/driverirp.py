# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl_v1.0
#

import volatility.framework.interfaces.plugins as plugins
from volatility.framework import constants
from volatility.framework import renderers, exceptions
from volatility.framework.configuration import requirements
from volatility.framework.renderers import format_hints
from volatility.plugins.windows import ssdt, driverscan

MAJOR_FUNCTIONS = [
    'IRP_MJ_CREATE', 'IRP_MJ_CREATE_NAMED_PIPE', 'IRP_MJ_CLOSE', 'IRP_MJ_READ', 'IRP_MJ_WRITE',
    'IRP_MJ_QUERY_INFORMATION', 'IRP_MJ_SET_INFORMATION', 'IRP_MJ_QUERY_EA', 'IRP_MJ_SET_EA', 'IRP_MJ_FLUSH_BUFFERS',
    'IRP_MJ_QUERY_VOLUME_INFORMATION', 'IRP_MJ_SET_VOLUME_INFORMATION', 'IRP_MJ_DIRECTORY_CONTROL',
    'IRP_MJ_FILE_SYSTEM_CONTROL', 'IRP_MJ_DEVICE_CONTROL', 'IRP_MJ_INTERNAL_DEVICE_CONTROL', 'IRP_MJ_SHUTDOWN',
    'IRP_MJ_LOCK_CONTROL', 'IRP_MJ_CLEANUP', 'IRP_MJ_CREATE_MAILSLOT', 'IRP_MJ_QUERY_SECURITY', 'IRP_MJ_SET_SECURITY',
    'IRP_MJ_POWER', 'IRP_MJ_SYSTEM_CONTROL', 'IRP_MJ_DEVICE_CHANGE', 'IRP_MJ_QUERY_QUOTA', 'IRP_MJ_SET_QUOTA',
    'IRP_MJ_PNP'
]


class DriverIrp(plugins.PluginInterface):
    """List IRPs for drivers in a particular windows memory image."""

    @classmethod
    def get_requirements(cls):
        return [
            requirements.PluginRequirement(name = 'ssdt', plugin = ssdt.SSDT, version = (1, 0, 0)),
            requirements.PluginRequirement(name = 'driverscan', plugin = driverscan.DriverScan, version = (1, 0, 0)),
            requirements.TranslationLayerRequirement(
                name = 'primary', description = 'Memory layer for the kernel', architectures = ["Intel32", "Intel64"]),
            requirements.SymbolTableRequirement(name = "nt_symbols", description = "Windows kernel symbols"),
        ]

    def _generator(self):

        collection = ssdt.SSDT.build_module_collection(self.context, self.config['primary'], self.config['nt_symbols'])

        for driver in driverscan.DriverScan.scan_drivers(self.context, self.config['primary'],
                                                         self.config['nt_symbols']):

            try:
                driver_name = driver.get_driver_name()
            except exceptions.InvalidAddressException:
                driver_name = renderers.NotApplicableValue()

            for i, address in enumerate(driver.MajorFunction):
                module_symbols = collection.get_module_symbols_by_absolute_location(address)

                for module_name, symbol_generator in module_symbols:
                    symbols_found = False

                    for symbol in symbol_generator:
                        symbols_found = True
                        yield (0, (format_hints.Hex(driver.vol.offset), driver_name, MAJOR_FUNCTIONS[i],
                                   format_hints.Hex(address), module_name, symbol.split(constants.BANG)[1]))

                    if not symbols_found:
                        yield (0, (format_hints.Hex(driver.vol.offset), driver_name, MAJOR_FUNCTIONS[i],
                                   format_hints.Hex(address), module_name, renderers.NotAvailableValue()))

    def run(self):

        return renderers.TreeGrid([
            ("Offset", format_hints.Hex),
            ("Driver Name", str),
            ("IRP", str),
            ("Address", format_hints.Hex),
            ("Module", str),
            ("Symbol", str),
        ], self._generator())
