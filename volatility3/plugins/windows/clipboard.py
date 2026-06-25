# This file is Copyright 2025 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
"""Plugin to extract clipboard data from Windows memory dumps."""

import logging
from typing import List

from volatility3.framework import interfaces, renderers, exceptions
from volatility3.framework.configuration import requirements
from volatility3.framework.renderers import format_hints
from volatility3.plugins.windows import pslist, vadinfo

vollog = logging.getLogger(__name__)


class Clipboard(interfaces.plugins.PluginInterface):
    """Extracts clipboard data from a Windows memory image."""

    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Windows kernel",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.VersionRequirement(
                name="pslist",
                component=pslist.PsList,
                version=(3, 0, 0),
            ),
            requirements.VersionRequirement(
                name="vadinfo",
                component=vadinfo.VadInfo,
                version=(2, 0, 0),
            ),
        ]

    def _generator(self):
        """Scan csrss.exe VADs for clipboard data."""
        kernel_name = self.config["kernel"]
        kernel = self.context.modules[kernel_name]

        for proc in pslist.PsList.list_processes(
            context=self.context,
            kernel_module_name=kernel_name,
        ):
            try:
                proc_name = proc.ImageFileName.cast(
                    "string",
                    max_length=proc.ImageFileName.vol.count,
                    errors="replace",
                ).lower()
            except exceptions.InvalidAddressException:
                continue

            if proc_name not in ("csrss.exe", "rdpclip.exe"):
                continue

            try:
                proc_id = int(proc.UniqueProcessId)
                proc_layer_name = proc.add_process_layer()
            except exceptions.InvalidAddressException:
                continue

            proc_layer = self.context.layers[proc_layer_name]

            protect_values = vadinfo.VadInfo.protect_values(
                self.context,
                kernel.layer_name,
                kernel.symbol_table_name,
            )

            for vad in vadinfo.VadInfo.list_vads(proc):
                try:
                    vad_start = vad.get_start()
                    vad_size = vad.get_size()
                    protection = vad.get_protection(
                        protect_values,
                        vadinfo.winnt_protections,
                    )
                    tag = vad.get_tag()
                except exceptions.InvalidAddressException:
                    continue

                if vad_size == 0 or vad_size > 0x200000:
                    continue

                if protection not in (
                    "PAGE_READWRITE",
                    "PAGE_READONLY",
                    "PAGE_EXECUTE_READ",
                    "PAGE_EXECUTE_READWRITE",
                ):
                    continue

                try:
                    data = proc_layer.read(vad_start, vad_size, pad=True)
                except exceptions.InvalidAddressException:
                    continue

                if not data:
                    continue

                # Try UTF-16-LE (most Windows clipboard text)
                try:
                    text = data.decode("utf-16-le", errors="ignore")
                    text = text.strip("\x00").strip()
                    if len(text) >= 4:
                        printable = "".join(
                            c for c in text if c.isprintable() or c in "\n\r\t"
                        )
                        if len(printable) >= 4:
                            yield (
                                0,
                                (
                                    proc_id,
                                    proc_name,
                                    format_hints.Hex(vad_start),
                                    "UTF16: " + printable[:256],
                                ),
                            )
                            continue
                except Exception:
                    pass

                # Try UTF-8 / ASCII
                try:
                    text = data.decode("utf-8", errors="ignore").strip("\x00").strip()
                    if len(text) >= 4:
                        printable = "".join(
                            c for c in text if c.isprintable() or c in "\n\r\t"
                        )
                        if len(printable) >= 4:
                            yield (
                                0,
                                (
                                    proc_id,
                                    proc_name,
                                    format_hints.Hex(vad_start),
                                    "ASCII: " + printable[:256],
                                ),
                            )
                except Exception:
                    pass
                
    def run(self):
        return renderers.TreeGrid(
            [
                ("PID", int),
                ("Process", str),
                ("Offset", format_hints.Hex),
                ("Data", str),
            ],
            self._generator(),
        )