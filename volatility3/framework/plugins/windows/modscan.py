# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
import logging
from typing import Iterable

from volatility3.framework import interfaces
from volatility3.framework.configuration import requirements
from volatility3.plugins.windows import poolscanner, dlllist, pslist, modules

vollog = logging.getLogger(__name__)


class ModScan(modules.Modules):
    """Scans for modules present in a particular windows memory image."""

    _required_framework_version = (2, 0, 0)
    _version = (2, 0, 0)

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
                name="poolscanner", component=poolscanner.PoolScanner, version=(1, 0, 0)
            ),
            requirements.VersionRequirement(
                name="modules", component=modules.Modules, version=(2, 0, 0)
            ),
            requirements.VersionRequirement(
                name="pslist", component=pslist.PsList, version=(2, 0, 0)
            ),
            requirements.VersionRequirement(
                name="dlllist", component=dlllist.DllList, version=(2, 0, 0)
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
        ]

    @classmethod
    def scan_modules(
        cls,
        context: interfaces.context.ContextInterface,
        layer_name: str,
        symbol_table: str,
    ) -> Iterable[interfaces.objects.ObjectInterface]:
        """Scans for modules using the poolscanner module and constraints.

        Args:
            context: The context to retrieve required elements (layers, symbol tables) from
            layer_name: The name of the layer on which to operate
            symbol_table: The name of the table containing the kernel symbols

        Returns:
            A list of Driver objects as found from the `layer_name` layer based on Driver pool signatures
        """

        constraints = poolscanner.PoolScanner.builtin_constraints(
            symbol_table, [b"MmLd"]
        )

        for result in poolscanner.PoolScanner.generate_pool_scan(
            context, layer_name, symbol_table, constraints
        ):
            _constraint, mem_object, _header = result
            yield mem_object
