# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

import datetime
from typing import Callable, Iterable, List

import volatility.framework.interfaces.plugins as plugins
from volatility.framework import renderers, interfaces, layers
from volatility.framework.configuration import requirements
from volatility.framework.objects import utility
from volatility.framework.renderers import format_hints
from volatility.plugins import timeliner


class PsList(plugins.PluginInterface, timeliner.TimeLinerInterface):
    """Lists the processes present in a particular windows memory image."""

    _version = (1, 0, 0)
    PHYSICAL_DEFAULT = False

    @classmethod
    def get_requirements(cls):
        return [
            requirements.TranslationLayerRequirement(name = 'primary',
                                                     description = 'Memory layer for the kernel',
                                                     architectures = ["Intel32", "Intel64"]),
            requirements.SymbolTableRequirement(name = "nt_symbols", description = "Windows kernel symbols"),
            # TODO: Convert this to a ListRequirement so that people can filter on sets of pids
            requirements.BooleanRequirement(name = 'physical',
                                            description = 'Display physical offsets instead of virtual',
                                            default = cls.PHYSICAL_DEFAULT,
                                            optional = True),
            requirements.IntRequirement(name = 'pid',
                                        description = "Process ID to include (all other processes are excluded)",
                                        optional = True)
        ]

    @classmethod
    def create_pid_filter(cls, pid_list: List[int] = None) -> Callable[[interfaces.objects.ObjectInterface], bool]:
        """A factory for producing filter functions that filter based on a list
        of process IDs.

        Args:
            pid_list: A list of process IDs that are acceptable, all other processes will be filtered out

        Returns:
            Filter function for passing to the `list_processes` method
        """
        filter_func = lambda _: False
        # FIXME: mypy #4973 or #2608
        pid_list = pid_list or []
        filter_list = [x for x in pid_list if x is not None]
        if filter_list:
            filter_func = lambda x: x.UniqueProcessId not in filter_list
        return filter_func

    @classmethod
    def create_name_filter(cls, name_list: List[str] = None) -> Callable[[interfaces.objects.ObjectInterface], bool]:
        """A factory for producing filter functions that filter based on a list
        of process names.

        Args:
            name_list: A list of process names that are acceptable, all other processes will be filtered out

        Returns:
            Filter function for passing to the `list_processes` method
        """
        filter_func = lambda _: False
        # FIXME: mypy #4973 or #2608
        name_list = name_list or []
        filter_list = [x for x in name_list if x is not None]
        if filter_list:
            filter_func = lambda x: utility.array_to_string(x.ImageFileName) not in filter_list
        return filter_func

    @classmethod
    def list_processes(cls,
                       context: interfaces.context.ContextInterface,
                       layer_name: str,
                       symbol_table: str,
                       filter_func: Callable[[interfaces.objects.ObjectInterface], bool] = lambda _: False) -> \
            Iterable[interfaces.objects.ObjectInterface]:
        """Lists all the processes in the primary layer that are in the pid
        config option.

        Args:
            context: The context to retrieve required elements (layers, symbol tables) from
            layer_name: The name of the layer on which to operate
            symbol_table: The name of the table containing the kernel symbols
            filter_func: A function which takes an EPROCESS object and returns True if the process should be ignored/filtered

        Returns:
            The list of EPROCESS objects from the `layer_name` layer's PsActiveProcessHead list after filtering
        """

        # We only use the object factory to demonstrate how to use one
        kvo = context.layers[layer_name].config['kernel_virtual_offset']
        ntkrnlmp = context.module(symbol_table, layer_name = layer_name, offset = kvo)

        ps_aph_offset = ntkrnlmp.get_symbol("PsActiveProcessHead").address
        list_entry = ntkrnlmp.object(object_type = "_LIST_ENTRY", offset = ps_aph_offset)

        # This is example code to demonstrate how to use symbol_space directly, rather than through a module:
        #
        # ```
        # reloff = self.context.symbol_space.get_type(
        #          self.config['nt_symbols'] + constants.BANG + "_EPROCESS").relative_child_offset(
        #          "ActiveProcessLinks")
        # ```
        #
        # Note: "nt_symbols!_EPROCESS" could have been used, but would rely on the "nt_symbols" symbol table not already
        # having been present.  Strictly, the value of the requirement should be joined with the BANG character
        # defined in the constants file
        reloff = ntkrnlmp.get_type("_EPROCESS").relative_child_offset("ActiveProcessLinks")
        eproc = ntkrnlmp.object(object_type = "_EPROCESS", offset = list_entry.vol.offset - reloff, absolute = True)

        for proc in eproc.ActiveProcessLinks:
            if not filter_func(proc):
                yield proc

    def _generator(self):

        memory = self.context.layers[self.config['primary']]
        if not isinstance(memory, layers.intel.Intel):
            raise TypeError("Primary layer is not an intel layer")

        for proc in self.list_processes(self.context,
                                        self.config['primary'],
                                        self.config['nt_symbols'],
                                        filter_func = self.create_pid_filter([self.config.get('pid', None)])):

            if not self.config.get('physical', self.PHYSICAL_DEFAULT):
                offset = proc.vol.offset
            else:
                (_, offset, _, _) = list(memory.mapping(offset = proc.vol.offset, length = 0))[0]

            yield (0, (proc.UniqueProcessId, proc.InheritedFromUniqueProcessId,
                       proc.ImageFileName.cast("string", max_length = proc.ImageFileName.vol.count, errors = 'replace'),
                       format_hints.Hex(offset), proc.ActiveThreads, proc.get_handle_count(), proc.get_session_id(),
                       proc.get_is_wow64(), proc.get_create_time(), proc.get_exit_time()))

    def generate_timeline(self):
        for row in self._generator():
            _depth, row_data = row
            description = "Process: {} ({})".format(row_data[2], row_data[3])
            yield (description, timeliner.TimeLinerType.CREATED, row_data[8])
            yield (description, timeliner.TimeLinerType.MODIFIED, row_data[9])

    def run(self):
        offsettype = "(V)" if not self.config.get('physical', self.PHYSICAL_DEFAULT) else "(P)"

        return renderers.TreeGrid([("PID", int), ("PPID", int), ("ImageFileName", str),
                                   ("Offset{0}".format(offsettype), format_hints.Hex), ("Threads", int),
                                   ("Handles", int), ("SessionId", int), ("Wow64", bool),
                                   ("CreateTime", datetime.datetime), ("ExitTime", datetime.datetime)],
                                  self._generator())
