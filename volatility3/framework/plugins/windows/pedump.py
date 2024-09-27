# This file is Copyright 2024 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
import logging
import ntpath
from typing import List, Type, Optional

from volatility3.framework import constants, exceptions, interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.symbols import intermed
from volatility3.framework.symbols.windows.extensions import pe
from volatility3.plugins.windows import pslist, modules

vollog = logging.getLogger(__name__)


class PEDump(interfaces.plugins.PluginInterface):
    """Allows extracting PE Files from a specific address in a specific address space"""

    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        # Since we're calling the plugin, make sure we have the plugin's requirements
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
                description="Process IDs to include (all other processes are excluded)",
                optional=True,
            ),
            requirements.IntRequirement(
                name="base",
                description="Base address to reconstruct a PE file",
                optional=False,
            ),
            requirements.BooleanRequirement(
                name="kernel_module",
                description="Extract from kernel address space.",
                default=False,
                optional=True,
            ),
        ]

    @classmethod
    def dump_pe(
        cls,
        context: interfaces.context.ContextInterface,
        pe_table_name: str,
        layer_name: str,
        open_method: Type[interfaces.plugins.FileHandlerInterface],
        file_name: str,
        base: int,
    ) -> Optional[str]:
        """
        Returns the filename of the dump file or None
        """
        try:
            file_handle = open_method(file_name)

            dos_header = context.object(
                pe_table_name + constants.BANG + "_IMAGE_DOS_HEADER",
                offset=base,
                layer_name=layer_name,
            )

            for offset, data in dos_header.reconstruct():
                file_handle.seek(offset)
                file_handle.write(data)
        except (
            IOError,
            exceptions.VolatilityException,
            OverflowError,
            ValueError,
        ) as excp:
            vollog.debug(f"Unable to dump PE file at offset {base}: {excp}")
            return None
        finally:
            file_handle.close()

        return file_handle.preferred_filename

    @classmethod
    def dump_ldr_entry(
        cls,
        context: interfaces.context.ContextInterface,
        pe_table_name: str,
        ldr_entry: interfaces.objects.ObjectInterface,
        open_method: Type[interfaces.plugins.FileHandlerInterface],
        layer_name: str = None,
        prefix: str = "",
    ) -> Optional[str]:
        """Extracts the PE file referenced an LDR_DATA_TABLE_ENTRY (DLL, kernel module) instance

        Args:
            context: the context to operate upon
            pe_table_name: the name for the symbol table containing the PE format symbols
            ldr_entry: the object representing the module
            open_method: class for constructing output files
            layer_name: the layer that the DLL lives within
            prefix: optional string to prepend to filename
        Returns:
            The output file name or None in the case of failure
        """
        try:
            name = ldr_entry.FullDllName.get_string()
        except exceptions.InvalidAddressException:
            name = "UnreadableDLLName"

        if layer_name is None:
            layer_name = ldr_entry.vol.layer_name

        file_name = "{}{}.{:#x}.{:#x}.dmp".format(
            prefix,
            ntpath.basename(name),
            ldr_entry.vol.offset,
            ldr_entry.DllBase,
        )

        return cls.dump_pe(
            context,
            pe_table_name,
            layer_name,
            open_method,
            file_name,
            ldr_entry.DllBase,
        )

    @classmethod
    def dump_pe_at_base(
        cls,
        context: interfaces.context.ContextInterface,
        pe_table_name: str,
        layer_name: str,
        open_method: Type[interfaces.plugins.FileHandlerInterface],
        proc_offset: int,
        pid: int,
        base: int,
    ) -> Optional[str]:
        file_name = "PE.{:#x}.{:d}.{:#x}.dmp".format(
            proc_offset,
            pid,
            base,
        )

        return PEDump.dump_pe(
            context, pe_table_name, layer_name, open_method, file_name, base
        )

    @classmethod
    def dump_kernel_pe_at_base(cls, context, kernel, pe_table_name, open_method, base):
        session_layers = modules.Modules.get_session_layers(
            context, kernel.layer_name, kernel.symbol_table_name
        )

        session_layer_name = modules.Modules.find_session_layer(
            context, session_layers, base
        )

        if session_layer_name:
            system_pid = 4

            file_output = PEDump.dump_pe_at_base(
                context,
                pe_table_name,
                session_layer_name,
                open_method,
                0,
                system_pid,
                base,
            )

            if file_output:
                yield system_pid, "Kernel", file_output
        else:
            vollog.warning(
                "Unable to find a session layer with the provided base address mapped in the kernel."
            )

    @classmethod
    def dump_processes(
        cls, context, kernel, pe_table_name, open_method, filter_func, base
    ):
        """ """

        for proc in pslist.PsList.list_processes(
            context=context,
            layer_name=kernel.layer_name,
            symbol_table=kernel.symbol_table_name,
            filter_func=filter_func,
        ):
            pid = proc.UniqueProcessId
            proc_name = proc.ImageFileName.cast(
                "string",
                max_length=proc.ImageFileName.vol.count,
                errors="replace",
            )
            proc_layer_name = proc.add_process_layer()

            file_output = PEDump.dump_pe_at_base(
                context,
                pe_table_name,
                proc_layer_name,
                open_method,
                proc.vol.offset,
                pid,
                base,
            )

            if file_output:
                yield pid, proc_name, file_output

    def _generator(self):
        kernel = self.context.modules[self.config["kernel"]]

        pe_table_name = intermed.IntermediateSymbolTable.create(
            self.context, self.config_path, "windows", "pe", class_types=pe.class_types
        )

        if self.config["kernel_module"] and self.config["pid"]:
            vollog.error("Only --kernel_module or --pid should be set. Not both")
            return

        if not self.config["kernel_module"] and not self.config["pid"]:
            vollog.error("--kernel_module or --pid must be set")
            return

        if self.config["kernel_module"]:
            pe_files = self.dump_kernel_pe_at_base(
                self.context, kernel, pe_table_name, self.open, self.config["base"]
            )
        else:
            filter_func = pslist.PsList.create_pid_filter(self.config.get("pid", None))
            pe_files = self.dump_processes(
                self.context,
                kernel,
                pe_table_name,
                self.open,
                filter_func,
                self.config["base"],
            )

        for pid, proc_name, file_output in pe_files:
            yield (
                0,
                (
                    pid,
                    proc_name,
                    file_output,
                ),
            )

    def run(self):
        return renderers.TreeGrid(
            [
                ("PID", int),
                ("Process", str),
                ("File output", str),
            ],
            self._generator(),
        )
