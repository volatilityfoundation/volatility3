# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

from typing import Iterable

from volatility3.framework import renderers, interfaces, exceptions
from volatility3.framework.configuration import requirements
from volatility3.framework.renderers import format_hints
from volatility3.plugins.windows import poolscanner


class MutantScan(interfaces.plugins.PluginInterface):
    """Scans for mutexes present in a particular windows memory image."""

    _required_framework_version = (2, 0, 0)
    _version = (2, 0, 0)

    @classmethod
    def get_requirements(cls):
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Windows kernel",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.VersionRequirement(
                name="poolscanner", component=poolscanner.PoolScanner, version=(3, 0, 0)
            ),
        ]

    @classmethod
    def scan_mutants(
        cls,
        context: interfaces.context.ContextInterface,
        kernel_module_name: str,
    ) -> Iterable[interfaces.objects.ObjectInterface]:
        """Scans for mutants using the poolscanner module and constraints.

        Args:
            context: The context to retrieve required elements (layers, symbol tables) from
            kernel_module_name: The name of the module for the kernel

        Returns:
              A list of Mutant objects found by scanning memory for the Mutant pool signatures
        """

        kernel = context.modules[kernel_module_name]

        constraints = poolscanner.PoolScanner.builtin_constraints(
            kernel.symbol_table_name, [b"Mut\xe1", b"Muta"]
        )

        for result in poolscanner.PoolScanner.generate_pool_scan(
            context, kernel_module_name, constraints
        ):
            _constraint, mem_object, _header = result
            yield mem_object

    def _generator(self):
        for mutant in self.scan_mutants(self.context, self.config["kernel"]):
            try:
                name = mutant.get_name()
            except (ValueError, exceptions.InvalidAddressException):
                name = renderers.NotApplicableValue()

            yield (0, (format_hints.Hex(mutant.vol.offset), name))

    def run(self):
        return renderers.TreeGrid(
            [
                ("Offset", format_hints.Hex),
                ("Name", str),
            ],
            self._generator(),
        )
