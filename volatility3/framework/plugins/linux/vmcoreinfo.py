# This file is Copyright 2024 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

from typing import List

from volatility3.framework import renderers, interfaces
from volatility3.framework.configuration import requirements
from volatility3.framework.interfaces import plugins
from volatility3.framework.symbols import linux
from volatility3.framework.renderers import format_hints


class VMCoreInfo(plugins.PluginInterface):
    """Enumerate VMCoreInfo tables"""

    _required_framework_version = (2, 11, 0)
    _version = (1, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.TranslationLayerRequirement(
                name="primary", description="Memory layer to scan"
            ),
            requirements.VersionRequirement(
                name="VMCoreInfo", component=linux.VMCoreInfo, version=(1, 0, 0)
            ),
        ]

    def _generator(self):
        layer_name = self.config["primary"]
        for (
            vmcoreinfo_offset,
            vmcoreinfo,
        ) in linux.VMCoreInfo.search_vmcoreinfo_elf_note(
            context=self.context,
            layer_name=layer_name,
        ):
            for key, value in vmcoreinfo.items():
                if key.startswith("SYMBOL(") or key == "KERNELOFFSET":
                    value = hex(value)
                else:
                    value = str(value)

                yield 0, (format_hints.Hex(vmcoreinfo_offset), key, value)

    def run(self):
        headers = [
            ("Offset", format_hints.Hex),
            ("Key", str),
            ("Value", str),
        ]
        return renderers.TreeGrid(headers, self._generator())
