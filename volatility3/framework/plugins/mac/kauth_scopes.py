# This file is opyright 2020 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

from typing import Iterable, Callable, Tuple

from volatility3.framework import renderers, interfaces, contexts
from volatility3.framework.configuration import requirements
from volatility3.framework.objects import utility
from volatility3.framework.renderers import format_hints
from volatility3.framework.symbols import mac
from volatility3.plugins.mac import lsmod


class Kauth_scopes(interfaces.plugins.PluginInterface):
    """ Lists kauth scopes and their status """

    _version = (1, 0, 0)
    _required_framework_version = (1, 0, 0)

    @classmethod
    def get_requirements(cls):
        return [
            requirements.TranslationLayerRequirement(name = 'primary',
                                                     description = 'Memory layer for the kernel',
                                                     architectures = ["Intel32", "Intel64"]),
            requirements.SymbolTableRequirement(name = "darwin", description = "Mac kernel"),
            requirements.VersionRequirement(name = 'macutils', component = mac.MacUtilities, version = (1, 1, 0)),
            requirements.PluginRequirement(name = 'lsmod', plugin = lsmod.Lsmod, version = (1, 0, 0))
        ]

    @classmethod
    def list_kauth_scopes(cls,
                          context: interfaces.context.ContextInterface,
                          layer_name: str,
                          darwin_symbols: str,
                          filter_func: Callable[[int], bool] = lambda _: False) -> \
            Iterable[Tuple[interfaces.objects.ObjectInterface,
                           interfaces.objects.ObjectInterface,
                           interfaces.objects.ObjectInterface]]:
        """
        Enumerates the registered kauth scopes and yields each object
        Uses smear-safe enumeration API
        """

        kernel = contexts.Module(context, darwin_symbols, layer_name, 0)

        scopes = kernel.object_from_symbol("kauth_scopes")

        for scope in mac.MacUtilities.walk_tailq(scopes, "ks_link"):
            yield scope

    def _generator(self):
        kernel = contexts.Module(self.context, self.config['darwin'], self.config['primary'], 0)

        mods = lsmod.Lsmod.list_modules(self.context, self.config['primary'], self.config['darwin'])

        handlers = mac.MacUtilities.generate_kernel_handler_info(self.context, self.config['primary'], kernel, mods)

        for scope in self.list_kauth_scopes(self.context, self.config['primary'], self.config['darwin']):

            callback = scope.ks_callback
            if callback == 0:
                continue

            module_name, symbol_name = mac.MacUtilities.lookup_module_address(self.context, handlers, callback)

            identifier = utility.pointer_to_string(scope.ks_identifier, 128)

            yield (0, (identifier, format_hints.Hex(scope.ks_idata), len([l for l in scope.get_listeners()]),
                       format_hints.Hex(callback), module_name, symbol_name))

    def run(self):
        return renderers.TreeGrid([("Name", str), ("IData", format_hints.Hex), ("Listeners", int),
                                   ("Callback Address", format_hints.Hex), ("Module", str), ("Symbol", str)],
                                  self._generator())
