import os
from volatility.framework.interfaces import plugins
from volatility.plugins.windows import modules
from volatility.framework import exceptions
from volatility.framework import contexts
from volatility.framework import constants
from volatility.framework.constants import windows as windows_constants
from volatility.framework import renderers
from volatility.framework.renderers import format_hints
from volatility.framework.configuration import requirements

class SSDT(plugins.PluginInterface):
    """Lists the system call table"""

    @classmethod
    def get_requirements(cls):
        return [requirements.TranslationLayerRequirement(name='primary',
                                                         description='Kernel Address Space',
                                                         architectures=["Intel32", "Intel64"]),
                requirements.SymbolRequirement(name="nt_symbols", description="Windows OS")]

    def _generator(self, modules):

        layer_name = self.config['primary']
        context_modules = []

        for mod in modules:

            try:
                module_name_with_ext = mod.BaseDllName.get_string()
            except exceptions.InvalidAddressException:
                # there's no use for a module with no name?
                continue

            module_name = os.path.splitext(module_name_with_ext)[0]

            if module_name in windows_constants.KERNEL_MODULE_NAMES:
                symbol_table_name = self.config["nt_symbols"]
            else:
                symbol_table_name = None

            context_module = contexts.SizedModule(self._context,
                                                  module_name,
                                                  layer_name,
                                                  mod.DllBase,
                                                  mod.SizeOfImage,
                                                  symbol_table_name)

            context_modules.append(context_module)

        collection = contexts.ModuleCollection(context_modules)

        kvo = self.context.memory[layer_name].config['kernel_virtual_offset']
        ntkrnlmp = self.context.module(self.config["nt_symbols"], layer_name=layer_name, offset=kvo)

        # this is just one way to enumerate the native (NT) service table.
        # to do the same thing for the Win32K service table, we would need Win32K.sys symbol support
        ## we could also find nt!KeServiceDescriptorTable (NT) and KeServiceDescriptorTableShadow (NT, Win32K)
        service_table_address = ntkrnlmp.get_symbol("KiServiceTable").address
        service_limit_address = ntkrnlmp.get_symbol("KiServiceLimit").address
        service_limit = ntkrnlmp.object(type_name="int", offset=kvo + service_limit_address)

        # on 32-bit systems the table indexes are 32-bits and contain pointers (unsigned)
        # on 64-bit systems the indexes are also 32-bits but they're offsets from the
        # base address of the table and can be negative, so we need a signed data type
        is_kernel_64 = ntkrnlmp.get_type("pointer").size == 8
        if is_kernel_64:
            array_subtype = "long"
            find_address = lambda func: kvo + service_table_address + (func >> 4)
        else:
            array_subtype = "unsigned long"
            find_address = lambda func: func

        functions = ntkrnlmp.object(type_name="array", offset=kvo + service_table_address,
                               subtype=ntkrnlmp.get_type(array_subtype),
                               count=service_limit)

        for idx, function in enumerate(functions):

            function = find_address(function)
            module_symbols = collection.get_module_symbols_by_absolute_location(function)

            for module_name, symbol_generator in module_symbols:
                symbols_found = False

                for symbol in symbol_generator:
                    symbols_found = True
                    yield (0, (idx,
                               format_hints.Hex(function),
                               module_name,
                               symbol.split(constants.BANG)[1]))

                if not symbols_found:
                    yield (0, (idx,
                               format_hints.Hex(function),
                               module_name,
                               renderers.NotAvailableValue()))

    def run(self):
        return renderers.TreeGrid([("Index", int),
                                   ("Address", format_hints.Hex),
                                   ("Module", str),
                                   ("Symbol", str)],
                                  self._generator(modules.Modules.list_modules(self.context,
                                                                               self.config['primary'],
                                                                               self.config['nt_symbols'])))
