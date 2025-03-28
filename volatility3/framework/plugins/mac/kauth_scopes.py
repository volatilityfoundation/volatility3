# This file is Copyright 2020 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
import logging
from typing import Iterable, Callable

from volatility3.framework import renderers, interfaces
from volatility3.framework.configuration import requirements
from volatility3.framework.objects import utility
from volatility3.framework.renderers import format_hints
from volatility3.framework.symbols import mac
from volatility3.plugins.mac import lsmod

vollog = logging.getLogger(__name__)


class Kauth_scopes(interfaces.plugins.PluginInterface):
    """Lists kauth scopes and their status"""

    _version = (2, 0, 0)
    _required_framework_version = (2, 0, 0)

    @classmethod
    def get_requirements(cls):
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Kernel module for the OS",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.VersionRequirement(
                name="macutils", component=mac.MacUtilities, version=(1, 1, 0)
            ),
            requirements.VersionRequirement(
                name="lsmod", component=lsmod.Lsmod, version=(2, 0, 0)
            ),
        ]

    @classmethod
    def list_kauth_scopes(
        cls,
        context: interfaces.context.ContextInterface,
        kernel_module_name: str,
        filter_func: Callable[[int], bool] = lambda _: False,
    ) -> Iterable[interfaces.objects.ObjectInterface]:
        """
        Enumerates the registered kauth scopes and yields each object
        Uses smear-safe enumeration API
        """
        kernel = context.modules[kernel_module_name]

        scopes = kernel.object_from_symbol("kauth_scopes")

        for scope in mac.MacUtilities.walk_tailq(scopes, "ks_link"):
            if not filter_func(scope):
                yield scope

    def _generator(self):
        kernel = self.context.modules[self.config["kernel"]]

        mods = lsmod.Lsmod.list_modules(self.context, self.config["kernel"])

        handlers = mac.MacUtilities.generate_kernel_handler_info(
            self.context, kernel.layer_name, kernel, mods
        )

        for scope in self.list_kauth_scopes(self.context, self.config["kernel"]):
            callback = scope.ks_callback
            if callback == 0:
                continue

            module_name, symbol_name = mac.MacUtilities.lookup_module_address(
                self.context, handlers, callback, self.config["kernel"]
            )

            identifier = utility.pointer_to_string(scope.ks_identifier, 128)

            yield (
                0,
                (
                    identifier,
                    format_hints.Hex(scope.ks_idata),
                    len([listener for listener in scope.get_listeners()]),
                    format_hints.Hex(callback),
                    module_name,
                    symbol_name,
                ),
            )

    def run(self):
        return renderers.TreeGrid(
            [
                ("Name", str),
                ("IData", format_hints.Hex),
                ("Listeners", int),
                ("Callback Address", format_hints.Hex),
                ("Module", str),
                ("Symbol", str),
            ],
            self._generator(),
        )
