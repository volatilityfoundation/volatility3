# This file is Copyright 2024 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
import logging
from typing import List

from volatility3.framework import renderers, interfaces, exceptions
from volatility3.framework.renderers import format_hints
from volatility3.framework.interfaces import plugins
from volatility3.framework.configuration import requirements

vollog = logging.getLogger(__name__)


class EBPF(plugins.PluginInterface):
    """Enumerate eBPF programs"""

    _required_framework_version = (2, 0, 0)

    _version = (1, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Linux kernel",
                architectures=["Intel32", "Intel64"],
            ),
        ]

    def get_ebpf_programs(self, vmlinux) -> interfaces.objects.ObjectInterface:
        """Enumerate eBPF programs walking its IDR.

        Args:
            vmlinux: The kernel symbols object

        Yields:
            eBPF program objects
        """
        if not vmlinux.has_symbol("prog_idr"):
            raise exceptions.VolatilityException(
                "Cannot find the eBPF prog idr. Unsupported kernel"
            )

        prog_idr = vmlinux.object_from_symbol("prog_idr")
        for page_addr in prog_idr.get_entries():
            bpf_prog = vmlinux.object("bpf_prog", offset=page_addr, absolute=True)
            yield bpf_prog

    def _generator(self):
        vmlinux = self.context.modules[self.config["kernel"]]
        for prog in self.get_ebpf_programs(vmlinux):
            prog_addr = prog.vol.offset
            prog_type = prog.get_type() or renderers.NotAvailableValue()
            prog_tag = prog.get_tag() or renderers.NotAvailableValue()
            prog_name = prog.get_name() or renderers.NotAvailableValue()
            fields = (format_hints.Hex(prog_addr), prog_name, prog_tag, prog_type)
            yield (0, fields)

    def run(self):
        headers = [
            ("Address", format_hints.Hex),
            ("Name", str),
            ("Tag", str),
            ("Type", str),
        ]
        return renderers.TreeGrid(headers, self._generator())
