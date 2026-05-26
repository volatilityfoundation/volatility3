# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

import datetime
from typing import Iterable

from volatility3.framework import renderers, exceptions, interfaces
from volatility3.framework.configuration import requirements
from volatility3.framework.renderers import format_hints
from volatility3.plugins import timeliner
from volatility3.plugins.windows import poolscanner


class SymlinkScan(interfaces.plugins.PluginInterface, timeliner.TimeLinerInterface):
    """Scans for links present in a particular windows memory image."""

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
                name="timeliner",
                component=timeliner.TimeLinerInterface,
                version=(1, 0, 0),
            ),
            requirements.VersionRequirement(
                name="poolscanner", component=poolscanner.PoolScanner, version=(3, 0, 0)
            ),
        ]

    @classmethod
    def scan_symlinks(
        cls,
        context: interfaces.context.ContextInterface,
        kernel_module_name: str,
    ) -> Iterable[interfaces.objects.ObjectInterface]:
        """Scans for links using the poolscanner module and constraints.

        Args:
            context: The context to retrieve required elements (layers, symbol tables) from
            layer_name: The name of the layer on which to operate
            symbol_table: The name of the table containing the kernel symbols

        Returns:
            A list of symlink objects found by scanning memory for the Symlink pool signatures
        """

        kernel = context.modules[kernel_module_name]

        constraints = poolscanner.PoolScanner.builtin_constraints(
            kernel.symbol_table_name, [b"Sym\xe2", b"Symb"]
        )

        for result in poolscanner.PoolScanner.generate_pool_scan(
            context, kernel_module_name, constraints
        ):
            _constraint, mem_object, _header = result
            yield mem_object

    def _generator(self):
        for link in self.scan_symlinks(self.context, self.config["kernel"]):
            try:
                from_name = link.get_link_name()
            except (ValueError, exceptions.InvalidAddressException):
                continue

            try:
                to_name = link.LinkTarget.String
            except exceptions.InvalidAddressException:
                continue

            yield (
                0,
                (
                    format_hints.Hex(link.vol.offset),
                    link.get_create_time(),
                    from_name,
                    to_name,
                ),
            )

    def generate_timeline(self):
        for row in self._generator():
            _depth, row_data = row
            description = f"Symlink: {row_data[2]} -> {row_data[3]}"
            yield (description, timeliner.TimeLinerType.CREATED, row_data[1])

    def run(self):
        return renderers.TreeGrid(
            [
                ("Offset", format_hints.Hex),
                ("CreateTime", datetime.datetime),
                ("From Name", str),
                ("To Name", str),
            ],
            self._generator(),
        )
