import volatility.framework.interfaces.plugins as plugins
from volatility.framework import renderers
from volatility.framework.configuration import requirements
from volatility.framework.renderers import format_hints


class PsList(plugins.PluginInterface):
    """Lists the processes present in a particular windows memory image"""

    PHYSICAL_DEFEAULT = False

    @classmethod
    def get_requirements(cls):
        return [requirements.TranslationLayerRequirement(name = 'primary',
                                                         description = 'Kernel Address Space',
                                                         architectures = ["Intel32", "Intel64"]),
                requirements.SymbolRequirement(name = "nt_symbols", description = "Windows OS"),
                # TODO: Convert this to a ListRequirement so that people can filter on sets of pids
                requirements.IntRequirement(name = 'pid',
                                            description = "Process ID to include (all other processes are excluded)",
                                            optional = True),
                requirements.BooleanRequirement(name = 'physical',
                                                description = 'Display physical offsets instead of virtual',
                                                default = cls.PHYSICAL_DEFEAULT,
                                                optional = True)]

    def update_configuration(self):
        """No operation since all values provided by config/requirements initially"""

    def _generator(self):
        for proc in self.list_processes():

            if not self.config.get('physical', self.PHYSICAL_DEFEAULT):
                offset = proc.vol.offset
            else:
                layer_name = self.config['primary']
                memory = self.context.memory[layer_name]
                (_, offset, _, _) = list(memory.mapping(offset = proc.vol.offset, length = 0))[0]

            yield (0, (proc.UniqueProcessId,
                       proc.InheritedFromUniqueProcessId,
                       proc.ImageFileName.cast("string",
                                               max_length = proc.ImageFileName.vol.count,
                                               errors = 'replace'),
                       format_hints.Hex(offset),
                       proc.ActiveThreads,
                       proc.get_handle_count(),
                       proc.get_session_id(),
                       proc.get_is_wow64(),
                       proc.get_create_time(),
                       proc.get_exit_time()))

    def list_processes(self):
        """Lists all the processes in the primary layer that are in the pid config option"""

        filter = lambda _: False
        if self.config.get('pid', None) is not None:
            filter = lambda x: x.UniqueProcessId not in [self.config['pid']]

        layer_name = self.config['primary']

        # We only use the object factory to demonstrate how to use one
        kvo = self.context.memory[layer_name].config['kernel_virtual_offset']
        ntkrnlmp = self.context.module(self.config['nt_symbols'], layer_name = layer_name, offset = kvo)

        ps_aph_offset = ntkrnlmp.get_symbol("PsActiveProcessHead").address
        list_entry = ntkrnlmp.object(type_name = "_LIST_ENTRY", offset = kvo + ps_aph_offset)

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
        eproc = ntkrnlmp.object(type_name = "_EPROCESS", offset = list_entry.vol.offset - reloff)

        for proc in eproc.ActiveProcessLinks:
            if not filter(proc):
                yield proc

    def run(self):
        offsettype = "(V)" if not self.config.get('physical', self.PHYSICAL_DEFEAULT) else "(P)"

        return renderers.TreeGrid([("PID", int),
                                   ("PPID", int),
                                   ("ImageFileName", str),
                                   ("Offset{0}".format(offsettype), format_hints.Hex),
                                   ("Threads", int),
                                   ("Handles", int),
                                   ("SessionId", int),
                                   ("Wow64", bool),
                                   ("CreateTime", str),
                                   ("ExitTime", str)],
                                  self._generator())
