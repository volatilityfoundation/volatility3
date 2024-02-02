# This file is Copyright 2023 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0

import logging, io, pefile
from volatility3.framework.symbols import intermed
from volatility3.framework import renderers, interfaces, exceptions, constants
from volatility3.framework.configuration import requirements
from volatility3.plugins.windows import pslist
from volatility3.framework.renderers import format_hints
from volatility3.framework.symbols.windows.extensions import pe

vollog = logging.getLogger(__name__)


class IAT(interfaces.plugins.PluginInterface):
    """Extract Import Address Table to list API (functions) used by a program contained in external libraries"""

    _required_framework_version = (2, 4, 0)

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
            requirements.ListRequirement(
                name="pid",
                element_type=int,
                description="Process ID to include (all other processes are excluded)",
                optional=True,
            ),
        ]

    def _generator(self, procs):
        kernel = self.context.modules[self.config["kernel"]]

        for proc in procs:
            try:
                proc_id = proc.UniqueProcessId
                proc_layer_name = proc.add_process_layer()
                peb = self.context.object(
                    kernel.symbol_table_name + constants.BANG + "_PEB",
                    layer_name=proc_layer_name,
                    offset=proc.Peb,
                )

                if proc_layer_name is None:
                    raise TypeError("add_process_layer failed")

                pe_table_name = intermed.IntermediateSymbolTable.create(
                    self.context,
                    self.config_path,
                    "windows",
                    "pe",
                    class_types=pe.class_types,
                )
                pe_data = io.BytesIO()

                dos_header = self.context.object(
                    pe_table_name + constants.BANG + "_IMAGE_DOS_HEADER",
                    offset=peb.ImageBaseAddress,
                    layer_name=proc_layer_name,
                )

                for offset, data in dos_header.reconstruct():
                    pe_data.seek(offset)
                    pe_data.write(data)

                pe_obj = pefile.PE(data=pe_data.getvalue(), fast_load=True)
                pe_obj.parse_data_directories(
                    [pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]]
                )
                if hasattr(pe_obj, "DIRECTORY_ENTRY_IMPORT"):
                    for entry in pe_obj.DIRECTORY_ENTRY_IMPORT:
                        dll_entry = entry.dll
                        if dll_entry:
                            dll_entry = dll_entry.decode()
                        else:
                            dll_entry = renderers.NotAvailableValue

                        bound = True
                        # Initially set to 0 if not bound
                        time_date_stamp = entry.struct.TimeDateStamp
                        if not time_date_stamp:
                            bound = False

                        # Iterate over imported functions
                        for imp in entry.imports:
                            import_name = imp.name
                            if import_name:
                                import_name = imp.name.decode()
                            else:
                                import_name = renderers.NotAvailableValue()
                            function_address = (
                                pe_obj.OPTIONAL_HEADER.ImageBase + imp.address
                            )
                            if not function_address:
                                function_address = renderers.NotAvailableValue

                            yield (
                                0,
                                (
                                    proc_id,
                                    proc.ImageFileName.cast(
                                        "string",
                                        max_length=proc.ImageFileName.vol.count,
                                        errors="replace",
                                    ),
                                    dll_entry,
                                    bound,
                                    import_name,
                                    format_hints.Hex(function_address),
                                ),
                            )
            except exceptions.InvalidAddressException as excp:
                vollog.debug(
                    "Process {}: invalid address {} in layer {}".format(
                        proc_id, excp.invalid_address, excp.layer_name
                    )
                )
                continue

    def run(self):
        kernel = self.context.modules[self.config["kernel"]]

        return renderers.TreeGrid(
            [
                ("PID", int),
                ("Name", str),
                ("Library", str),
                ("Bound", bool),
                ("Function", str),
                ("Address", format_hints.Hex),
            ],
            self._generator(
                pslist.PsList.list_processes(
                    context=self.context,
                    layer_name=kernel.layer_name,
                    symbol_table=kernel.symbol_table_name,
                    filter_func=pslist.PsList.create_pid_filter(
                        self.config.get("pid", None)
                    ),
                )
            ),
        )
