# This file is Copyright 2024 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

import logging

from volatility3.framework import constants, exceptions, interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.renderers import format_hints
from volatility3.framework.symbols import intermed
from volatility3.framework.symbols.windows.extensions import pe
from volatility3.plugins.windows import pslist, vadinfo

vollog = logging.getLogger(__name__)


class LdrModules(interfaces.plugins.PluginInterface):
    """Lists the loaded modules in a particular windows memory image."""

    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 1)

    @classmethod
    def get_requirements(cls):
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Windows kernel",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.VersionRequirement(
                name="pslist", component=pslist.PsList, version=(2, 0, 0)
            ),
            requirements.VersionRequirement(
                name="vadinfo", component=vadinfo.VadInfo, version=(2, 0, 0)
            ),
            requirements.ListRequirement(
                name="pid",
                element_type=int,
                description="Process IDs to include (all other processes are excluded)",
                optional=True,
            ),
        ]

    def _generator(self, procs):
        pe_table_name = intermed.IntermediateSymbolTable.create(
            self.context, self.config_path, "windows", "pe", class_types=pe.class_types
        )

        def filter_function(x: interfaces.objects.ObjectInterface) -> bool:
            try:
                return not (x.get_private_memory() == 0 and x.ControlArea)
            except AttributeError:
                return False

        filter_func = filter_function

        for proc in procs:
            proc_layer_name = proc.add_process_layer()

            # Build dictionaries from different module lists, where the DllBase address is the key and value is the module object
            load_order_mod = dict(
                (mod.DllBase, mod) for mod in proc.load_order_modules()
            )
            init_order_mod = dict(
                (mod.DllBase, mod) for mod in proc.init_order_modules()
            )
            mem_order_mod = dict((mod.DllBase, mod) for mod in proc.mem_order_modules())

            # Build dictionary of mapped files, where the VAD start address is the key and value is the file name of the mapped file
            mapped_files = {}
            for vad in vadinfo.VadInfo.list_vads(proc, filter_func=filter_func):
                dos_header = self.context.object(
                    pe_table_name + constants.BANG + "_IMAGE_DOS_HEADER",
                    offset=vad.get_start(),
                    layer_name=proc_layer_name,
                )
                try:
                    # Filter out VADs that do not start with a MZ header
                    if dos_header.e_magic != 0x5A4D:
                        continue
                except exceptions.InvalidAddressException:
                    vollog.log(
                        constants.LOGLEVEL_VVVV,
                        f"Skipping vad at {hex(dos_header.vol.offset)} due to InvalidAddressException",
                    )
                    continue

                mapped_files[vad.get_start()] = vad.get_file_name()

            for base in mapped_files.keys():
                # Does the base address exist in the PEB DLL lists?
                load_mod = load_order_mod.get(base, None)
                init_mod = init_order_mod.get(base, None)
                mem_mod = mem_order_mod.get(base, None)

                yield (
                    0,
                    [
                        int(proc.UniqueProcessId),
                        str(
                            proc.ImageFileName.cast(
                                "string",
                                max_length=proc.ImageFileName.vol.count,
                                errors="replace",
                            )
                        ),
                        format_hints.Hex(base),
                        load_mod is not None,
                        init_mod is not None,
                        mem_mod is not None,
                        mapped_files[base],
                    ],
                )

    def run(self):
        filter_func = pslist.PsList.create_pid_filter(self.config.get("pid", None))
        kernel = self.context.modules[self.config["kernel"]]

        return renderers.TreeGrid(
            [
                ("Pid", int),
                ("Process", str),
                ("Base", format_hints.Hex),
                ("InLoad", bool),
                ("InInit", bool),
                ("InMem", bool),
                ("MappedPath", str),
            ],
            self._generator(
                pslist.PsList.list_processes(
                    context=self.context,
                    layer_name=kernel.layer_name,
                    symbol_table=kernel.symbol_table_name,
                    filter_func=filter_func,
                )
            ),
        )
