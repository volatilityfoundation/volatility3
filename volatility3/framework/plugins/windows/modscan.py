# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
import logging
from typing import Iterable

from volatility3.framework import interfaces
from volatility3.framework.configuration import requirements
from volatility3.plugins.windows import poolscanner, modules, pedump

vollog = logging.getLogger(__name__)


class ModScan(modules.Modules):
    """Scans for modules present in a particular windows memory image."""

    _required_framework_version = (2, 0, 0)

    # 3.0.0 changed the signature of enumeration methods (scan_modules)
    _version = (3, 0, 0)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._enumeration_method = self.scan_modules

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
            requirements.VersionRequirement(
                name="modules", component=modules.Modules, version=(3, 0, 0)
            ),
            requirements.BooleanRequirement(
                name="dump",
                description="Extract listed modules",
                default=False,
                optional=True,
            ),
            requirements.IntRequirement(
                name="base",
                description="Extract a single module with BASE address",
                optional=True,
            ),
            requirements.StringRequirement(
                name="name",
                description="module name/sub string",
                optional=True,
                default=None,
            ),
            requirements.VersionRequirement(
                name="pedump", component=pedump.PEDump, version=(2, 0, 0)
            ),
        ]

    @classmethod
    def scan_modules(
        cls,
        context: interfaces.context.ContextInterface,
        kernel_module_name: str,
    ) -> Iterable[interfaces.objects.ObjectInterface]:
        """Scans for modules using the poolscanner module and constraints.

        Args:
            context: The context to retrieve required elements (layers, symbol tables) from
            kernel_module_name: Name of the module for the kernel
        Returns:
            A list of kernel module objects as found from the primary (kernel) layer based on module pool signatures
        """

        kernel = context.modules[kernel_module_name]

        constraints = poolscanner.PoolScanner.builtin_constraints(
            kernel.symbol_table_name, [b"MmLd"]
        )

        for result in poolscanner.PoolScanner.generate_pool_scan(
            context, kernel_module_name, constraints
        ):
            _constraint, mem_object, _header = result
            yield mem_object
