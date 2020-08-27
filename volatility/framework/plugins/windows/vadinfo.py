# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

import logging
from typing import Callable, List, Generator, Iterable

from volatility.framework import renderers, interfaces
from volatility.framework.configuration import requirements
from volatility.framework.objects import utility
from volatility.framework.renderers import format_hints
from volatility.plugins.windows import pslist

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

    _version = (1, 1, 0)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._protect_values = None

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        # Since we're calling the plugin, make sure we have the plugin's requirements
        return [requirements.TranslationLayerRequirement(name = 'primary',
                                                         description = 'Memory layer for the kernel',
                                                         architectures = ["Intel32", "Intel64"]),
                requirements.SymbolTableRequirement(name = "nt_symbols", description = "Windows kernel symbols"),
                # TODO: Convert this to a ListRequirement so that people can filter on sets of ranges
                requirements.IntRequirement(name = 'address',
                                            description = "Process virtual memory address to include " \
                                                          "(all other address ranges are excluded). This must be " \
                                                          "a base address, not an address within the desired range.",
                                            optional = True),
                requirements.ListRequirement(name = 'pid',
                                             description = 'Filter on specific process IDs',
                                             element_type = int,
                                             optional = True),
                requirements.PluginRequirement(name = 'pslist', plugin = pslist.PsList, version = (1, 0, 0)),
                requirements.BooleanRequirement(name = 'dump',
                                                description = "Extract listed memory ranges",
                                                default = False,
                                                optional = True)
                ]

    @classmethod
    def protect_values(cls, context: interfaces.context.ContextInterface, layer_name: str,
                       symbol_table: str) -> Iterable[int]:
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
        ntkrnlmp = context.module(symbol_table, layer_name = layer_name, offset = kvo)
        addr = ntkrnlmp.get_symbol("MmProtectToValue").address
        values = ntkrnlmp.object(object_type = "array", offset = addr, subtype = ntkrnlmp.get_type("int"), count = 32)
        return values  # type: ignore

    @classmethod
    def list_vads(cls, proc: interfaces.objects.ObjectInterface,
                  filter_func: Callable[[interfaces.objects.ObjectInterface], bool] = lambda _: False) -> \
            Generator[interfaces.objects.ObjectInterface, None, None]:
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
    def vad_dump(cls, context: interfaces.context.ContextInterface, layer_name: str,
                 vad: interfaces.objects.ObjectInterface) -> bytes:
        """Extracts the complete data for Vad as a FileInterface

        Args:
            context: the context to operate upon
            layer_name: the name of the layer that the VAD lives within
            vad: the virtual address descriptor to be dumped

        Returns:
            bytes containing the data from the vad
        """

        tmp_data = b""
        proc_layer = context.layers[layer_name]
        chunk_size = 1024 * 1024 * 10
        offset = vad.get_start()
        out_of_range = vad.get_end()
        # print("walking from {:x} to {:x} | {:x}".format(offset, out_of_range, out_of_range-offset))
        while offset < out_of_range:
            to_read = min(chunk_size, out_of_range - offset)
            data = proc_layer.read(offset, to_read, pad = True)
            if not data:
                break
            tmp_data += data
            offset += to_read

        return tmp_data

    def _generator(self, procs):

        def passthrough(_: interfaces.objects.ObjectInterface) -> bool:
            return False

        filter_func = passthrough
        if self.config.get('address', None) is not None:

            def filter_function(x: interfaces.objects.ObjectInterface) -> bool:
                return x.get_start() not in [self.config['address']]

            filter_func = filter_function

        for proc in procs:
            process_name = utility.array_to_string(proc.ImageFileName)
            proc_layer_name = proc.add_process_layer()

            for vad in self.list_vads(proc, filter_func = filter_func):

                dumped = False
                if self.config['dump']:
                    data = self.vad_dump(self.context, proc_layer_name, vad)
                    filedata = interfaces.plugins.FileInterface("pid.{0}.vad.{1:#x}-{2:#x}.dmp".format(
                        proc.UniqueProcessId, vad.get_start(), vad.get_end()))
                    filedata.data.write(data)
                    self.produce_file(filedata)
                    dumped = True

                yield (0, (proc.UniqueProcessId, process_name, format_hints.Hex(vad.vol.offset),
                           format_hints.Hex(vad.get_start()), format_hints.Hex(vad.get_end()), vad.get_tag(),
                           vad.get_protection(
                               self.protect_values(self.context, self.config['primary'], self.config['nt_symbols']),
                               winnt_protections), vad.get_commit_charge(), vad.get_private_memory(),
                           format_hints.Hex(vad.get_parent()), vad.get_file_name(), dumped))

    def run(self):

        filter_func = pslist.PsList.create_pid_filter(self.config.get('pid', None))

        return renderers.TreeGrid([("PID", int), ("Process", str), ("Offset", format_hints.Hex),
                                   ("Start VPN", format_hints.Hex), ("End VPN", format_hints.Hex), ("Tag", str),
                                   ("Protection", str), ("CommitCharge", int), ("PrivateMemory", int),
                                   ("Parent", format_hints.Hex), ("File", str), ("Dumped", bool)],
                                  self._generator(
                                      pslist.PsList.list_processes(context = self.context,
                                                                   layer_name = self.config['primary'],
                                                                   symbol_table = self.config['nt_symbols'],
                                                                   filter_func = filter_func)))
