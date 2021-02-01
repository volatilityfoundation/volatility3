# This file is opyright 2020 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

from volatility3.framework import renderers, interfaces, contexts
from volatility3.framework.configuration import requirements
from volatility3.framework.objects import utility
from volatility3.framework.renderers import format_hints
from volatility3.framework.symbols import mac
from volatility3.plugins.mac import lsmod, kauth_scopes


class Kauth_listeners(interfaces.plugins.PluginInterface):
    """ Lists kauth listeners and their status """

    _required_framework_version = (1, 0, 0)

    @classmethod
    def get_requirements(cls):
        return [
            requirements.TranslationLayerRequirement(name = 'primary',
                                                     description = 'Memory layer for the kernel',
                                                     architectures = ["Intel32", "Intel64"]),
            requirements.SymbolTableRequirement(name = "darwin", description = "Mac kernel"),
            requirements.VersionRequirement(name = 'macutils', component = mac.MacUtilities, version = (1, 1, 0)),
            requirements.PluginRequirement(name = 'lsmod', plugin = lsmod.Lsmod, version = (1, 0, 0)),
            requirements.PluginRequirement(name = 'kauth_scopes',
                                           plugin = kauth_scopes.Kauth_scopes,
                                           version = (1, 0, 0))
        ]

    def _generator(self):
        """
        Enumerates the listeners for each kauth scope
        """
        kernel = contexts.Module(self.context, self.config['darwin'], self.config['primary'], 0)

        mods = lsmod.Lsmod.list_modules(self.context, self.config['primary'], self.config['darwin'])

        handlers = mac.MacUtilities.generate_kernel_handler_info(self.context, self.config['primary'], kernel, mods)

        for scope in kauth_scopes.Kauth_scopes.list_kauth_scopes(self.context, self.config['primary'],
                                                                 self.config['darwin']):

            scope_name = utility.pointer_to_string(scope.ks_identifier, 128)

            for listener in scope.get_listeners():
                callback = listener.kll_callback
                if callback == 0:
                    continue

                module_name, symbol_name = mac.MacUtilities.lookup_module_address(self.context, handlers, callback)

                yield (0, (scope_name, format_hints.Hex(listener.kll_idata), format_hints.Hex(callback), module_name,
                           symbol_name))

    def run(self):
        return renderers.TreeGrid([("Name", str), ("IData", format_hints.Hex), ("Callback Address", format_hints.Hex),
                                   ("Module", str), ("Symbol", str)], self._generator())
