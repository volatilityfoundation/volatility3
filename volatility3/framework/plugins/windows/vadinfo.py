# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

import logging
from typing import Callable, List, Generator, Iterable, Type, Optional, Tuple

from volatility3.framework import renderers, interfaces, exceptions, symbols
from volatility3.framework.configuration import requirements
from volatility3.framework.objects import utility
from volatility3.framework.renderers import format_hints
from volatility3.plugins.windows import pslist, pe_symbols

vollog = logging.getLogger(__name__)

# these are from WinNT.h
winnt_protections = {
    "PAGE_NOACCESS": 0x01,
    "PAGE_READONLY": 0x02,
    "PAGE_READWRITE": 0x04,
    "PAGE_WRITECOPY": 0x08,
    "PAGE_EXECUTE": 0x10,
    "PAGE_EXECUTE_READ": 0x20,
    "PAGE_EXECUTE_READWRITE": 0x40,
    "PAGE_EXECUTE_WRITECOPY": 0x80,
    "PAGE_GUARD": 0x100,
    "PAGE_NOCACHE": 0x200,
    "PAGE_WRITECOMBINE": 0x400,
    "PAGE_TARGETS_INVALID": 0x40000000,
}


class VadInfo(interfaces.plugins.PluginInterface):
    """Lists process memory ranges."""

    _required_framework_version = (2, 4, 0)
    _version = (2, 0, 0)
    MAXSIZE_DEFAULT = 1024 * 1024 * 1024  # 1 Gb

    def __init__(self, *args, **kwargs):  # type: ignore
        super().__init__(*args, **kwargs)
        self._protect_values = None

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        # Since we're calling the plugin, make sure we have the plugin's requirements
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Windows kernel",
                architectures=["Intel32", "Intel64"],
            ),
            # TODO: Convert this to a ListRequirement so that people can filter on sets of ranges
            requirements.IntRequirement(
                name="address",
                description="Process virtual memory address to include "
                "(all other address ranges are excluded).",
                optional=True,
            ),
            requirements.ListRequirement(
                name="pid",
                description="Filter on specific process IDs",
                element_type=int,
                optional=True,
            ),
            requirements.PluginRequirement(
                name="pslist", plugin=pslist.PsList, version=(2, 0, 0)
            ),
            requirements.BooleanRequirement(
                name="dump",
                description="Extract listed memory ranges",
                default=False,
                optional=True,
            ),
            requirements.IntRequirement(
                name="maxsize",
                description="Maximum size for dumped VAD sections "
                "(all the bigger sections will be ignored)",
                default=cls.MAXSIZE_DEFAULT,
                optional=True,
            ),
        ]

    @classmethod
    def protect_values(
        cls,
        context: interfaces.context.ContextInterface,
        layer_name: str,
        symbol_table: str,
    ) -> Iterable[int]:
        """Look up the array of memory protection constants from the memory
        sample. These don't change often, but if they do in the future, then
        finding them dynamically versus hard-coding here will ensure we parse
        them properly.

        Args:
            context: The context to retrieve required elements (layers, symbol tables) from
            layer_name: The name of the layer on which to operate
            symbol_table: The name of the table containing the kernel symbols
        """

        kvo = context.layers[layer_name].config["kernel_virtual_offset"]
        ntkrnlmp = context.module(symbol_table, layer_name=layer_name, offset=kvo)
        addr = ntkrnlmp.get_symbol("MmProtectToValue").address
        values = ntkrnlmp.object(
            object_type="array", offset=addr, subtype=ntkrnlmp.get_type("int"), count=32
        )
        return values  # type: ignore

    @staticmethod
    def get_proc_vads_with_file_paths(
        proc: interfaces.objects.ObjectInterface,
    ) -> pe_symbols.PESymbols.ranges_type:
        """
        Returns a list of the process' vads that map a file
        """
        vads = []

        for vad in proc.get_vad_root().traverse():
            filepath = vad.get_file_name()
            if not isinstance(filepath, str) or filepath.count("\\") == 0:
                continue

            vads.append((vad.get_start(), vad.get_size(), filepath))

        return vads

    @classmethod
    def get_all_vads_with_file_paths(
        cls,
        context: interfaces.context.ContextInterface,
        layer_name: str,
        symbol_table_name: str,
    ) -> Generator[
        Tuple[
            interfaces.objects.ObjectInterface, str, pe_symbols.PESymbols.ranges_type
        ],
        None,
        None,
    ]:
        """
        Yields each set of vads for a process that have a file mapped, along with the process itself and its layer
        """
        is_32bit_arch = not symbols.symbol_table_is_64bit(context, symbol_table_name)

        procs = pslist.PsList.list_processes(
            context=context,
            layer_name=layer_name,
            symbol_table=symbol_table_name,
        )

        for proc in procs:
            try:
                proc_layer_name = proc.add_process_layer()
            except exceptions.InvalidAddressException:
                continue

            vads = cls.get_proc_vads_with_file_paths(proc)

            yield proc, proc_layer_name, vads

    @classmethod
    def list_vads(
        cls,
        proc: interfaces.objects.ObjectInterface,
        filter_func: Callable[
            [interfaces.objects.ObjectInterface], bool
        ] = lambda _: False,
    ) -> Generator[interfaces.objects.ObjectInterface, None, None]:
        """Lists the Virtual Address Descriptors of a specific process.

        Args:
            proc: _EPROCESS object from which to list the VADs
            filter_func: Function to take a virtual address descriptor value and return True if it should be filtered out

        Returns:
            A list of virtual address descriptors based on the process and filtered based on the filter function
        """
        for vad in proc.get_vad_root().traverse():
            if not filter_func(vad):
                yield vad

    @classmethod
    def vad_dump(
        cls,
        context: interfaces.context.ContextInterface,
        proc: interfaces.objects.ObjectInterface,
        vad: interfaces.objects.ObjectInterface,
        open_method: Type[interfaces.plugins.FileHandlerInterface],
        maxsize: int = MAXSIZE_DEFAULT,
    ) -> Optional[interfaces.plugins.FileHandlerInterface]:
        """Extracts the complete data for Vad as a FileInterface.

        Args:
            context: The context to retrieve required elements (layers, symbol tables) from
            proc: an _EPROCESS instance
            vad: The suspected VAD to extract (ObjectInterface)
            open_method: class to provide context manager for opening the file
            maxsize: Max size of VAD section (default MAXSIZE_DEFAULT)

        Returns:
            An open FileInterface object containing the complete data for the process or None in the case of failure
        """

        try:
            vad_start = vad.get_start()
            vad_end = vad.get_end()
        except AttributeError:
            vollog.debug("Unable to find the starting/ending VPN member")
            return None

        if 0 < maxsize < vad.get_size():
            vollog.debug(
                f"Skip VAD dump {vad_start:#x}-{vad_end:#x} due to maxsize limit"
            )
            return None

        proc_id = "Unknown"
        try:
            proc_id = proc.UniqueProcessId
            proc_layer_name = proc.add_process_layer()
        except exceptions.InvalidAddressException as excp:
            vollog.debug(
                "Process {}: invalid address {} in layer {}".format(
                    proc_id, excp.invalid_address, excp.layer_name
                )
            )
            return None

        proc_layer = context.layers[proc_layer_name]
        file_name = f"pid.{proc_id}.vad.{vad_start:#x}-{vad_end:#x}.dmp"
        try:
            file_handle = open_method(file_name)
            chunk_size = 1024 * 1024 * 10
            offset = vad_start
            vad_size = vad.get_size()
            while offset < vad_start + vad_size:
                to_read = min(chunk_size, vad_start + vad_size - offset)
                data = proc_layer.read(offset, to_read, pad=True)
                if not data:
                    break
                file_handle.write(data)
                offset += to_read

        except Exception as excp:
            vollog.debug(f"Unable to dump VAD {file_name}: {excp}")
            return None

        return file_handle

    def _generator(
        self, procs: List[interfaces.objects.ObjectInterface]) -> Generator[
        Tuple[
            int,
            Tuple[
                int,
                str,
                format_hints.Hex,
                format_hints.Hex,
                format_hints.Hex,
                str,
                str,
                int,
                int,
                format_hints.Hex,
                str,
                str,
            ],
        ],
        None,
        None,
    ]:
        kernel = self.context.modules[self.config["kernel"]]
        kernel_layer = self.context.layers[kernel.layer_name]

        def passthrough(x: interfaces.objects.ObjectInterface) -> bool:
            return False

        filter_func = passthrough
        if self.config.get("address", None) is not None:

            def filter_function(x: interfaces.objects.ObjectInterface) -> bool:
                return not (x.get_start() <= self.config["address"] <= x.get_end())

            filter_func = filter_function

        for proc in procs:
            process_name = utility.array_to_string(proc.ImageFileName)

            for vad in self.list_vads(proc, filter_func=filter_func):
                file_output = "Disabled"
                if self.config["dump"]:
                    file_handle = self.vad_dump(
                        self.context, proc, vad, self.open, self.config["maxsize"]
                    )
                    file_output = "Error outputting file"
                    if file_handle:
                        file_handle.close()
                        file_output = file_handle.preferred_filename

                yield (
                    0,
                    (
                        proc.UniqueProcessId,
                        process_name,
                        format_hints.Hex(kernel_layer.canonicalize(vad.vol.offset)),
                        format_hints.Hex(vad.get_start()),
                        format_hints.Hex(vad.get_end()),
                        vad.get_tag(),
                        vad.get_protection(
                            self.protect_values(
                                self.context,
                                kernel.layer_name,
                                kernel.symbol_table_name,
                            ),
                            winnt_protections,
                        ),
                        vad.get_commit_charge(),
                        vad.get_private_memory(),
                        format_hints.Hex(vad.get_parent()),
                        vad.get_file_name(),
                        file_output,
                    ),
                )

    def run(self) -> renderers.TreeGrid:
        kernel = self.context.modules[self.config["kernel"]]

        filter_func = pslist.PsList.create_pid_filter(self.config.get("pid", None))

        return renderers.TreeGrid(
            [
                ("PID", int),
                ("Process", str),
                ("Offset", format_hints.Hex),
                ("Start VPN", format_hints.Hex),
                ("End VPN", format_hints.Hex),
                ("Tag", str),
                ("Protection", str),
                ("CommitCharge", int),
                ("PrivateMemory", int),
                ("Parent", format_hints.Hex),
                ("File", str),
                ("File output", str),
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
