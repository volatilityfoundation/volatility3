# This file is Copyright 2020 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

from volatility3.framework import renderers, interfaces
from volatility3.framework.configuration import requirements
from volatility3.framework.objects import utility
from volatility3.framework.renderers import format_hints
from volatility3.framework.symbols import mac
from volatility3.plugins.mac import lsmod, kauth_scopes


class Kauth_listeners(interfaces.plugins.PluginInterface):
    """Lists kauth listeners and their status"""

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
            requirements.VersionRequirement(
                name="kauth_scopes",
                component=kauth_scopes.Kauth_scopes,
                version=(2, 0, 0),
            ),
        ]

    def _generator(self):
        """
        Enumerates the listeners for each kauth scope
        """
        kernel = self.context.modules[self.config["kernel"]]

        mods = lsmod.Lsmod.list_modules(self.context, self.config["kernel"])

        handlers = mac.MacUtilities.generate_kernel_handler_info(
            self.context, kernel.layer_name, kernel, mods
        )

        for scope in kauth_scopes.Kauth_scopes.list_kauth_scopes(
            self.context, self.config["kernel"]
        ):
            scope_name = utility.pointer_to_string(scope.ks_identifier, 128)

            for listener in scope.get_listeners():
                callback = listener.kll_callback
                if callback == 0:
                    continue

                module_name, symbol_name = mac.MacUtilities.lookup_module_address(
                    self.context, handlers, callback, self.config["kernel"]
                )

                yield (
                    0,
                    (
                        scope_name,
                        format_hints.Hex(listener.kll_idata),
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
                ("Callback Address", format_hints.Hex),
                ("Module", str),
                ("Symbol", str),
            ],
            self._generator(),
        )
