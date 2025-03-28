# This file is Copyright 2025 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
import logging
from typing import List

from volatility3 import framework
import volatility3.framework.symbols.linux.utilities.module_extract as linux_utilities_module_extract
from volatility3.framework import interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.renderers import format_hints
from volatility3.framework.objects import utility

vollog = logging.getLogger(__name__)


class ModuleExtract(interfaces.plugins.PluginInterface):
    """Recreates an ELF file from a specific address in the kernel"""

    _version = (1, 0, 0)
    _required_framework_version = (2, 25, 0)

    framework.require_interface_version(*_required_framework_version)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        # Since we're calling the plugin, make sure we have the plugin's requirements
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Windows kernel",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.IntRequirement(
                name="base",
                description="Base virtual address to reconstruct an ELF file",
                optional=False,
            ),
        ]

    def _generator(self):
        kernel = self.context.modules[self.config["kernel"]]

        base_address = self.config["base"]

        kernel_layer = self.context.layers[kernel.layer_name]

        if not kernel_layer.is_valid(base_address):
            vollog.error(
                f"Given base address ({base_address:#x}) is not valid in the kernel address space. Unable to extract file."
            )
            return

        module = kernel.object(object_type="module", offset=base_address, absolute=True)

        elf_data = linux_utilities_module_extract.ModuleExtract.extract_module(
            self.context, self.config["kernel"], module
        )
        if not elf_data:
            vollog.error(
                f"Unable to reconstruct the ELF for module struct at {base_address:#x}"
            )
            return

        module_name = utility.array_to_string(module.name)
        file_name = self.open.sanitize_filename(
            f"kernel_module.{module_name}.{base_address:#x}.elf"
        )

        with self.open(file_name) as file_handle:
            file_handle.write(elf_data)

        yield 0, (
            format_hints.Hex(base_address),
            len(elf_data),
            file_handle.preferred_filename,
        )

    def run(self):
        return renderers.TreeGrid(
            [
                ("Base", format_hints.Hex),
                ("File Size", int),
                ("File output", str),
            ],
            self._generator(),
        )
