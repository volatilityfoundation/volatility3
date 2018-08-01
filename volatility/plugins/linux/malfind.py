import volatility.framework.interfaces.plugins as interfaces_plugins
import volatility.framework.interfaces.renderers as interfaces_renderers
import volatility.plugins.linux.pslist as pslist
from volatility.framework import constants
from volatility.framework import renderers
from volatility.framework.objects import utility
from volatility.framework.renderers import format_hints

class Malfind(interfaces_plugins.PluginInterface):
    """Lists process memory ranges that potentially contain injected code"""

    @classmethod
    def get_requirements(cls):
        # Since we're calling the plugin, make sure we have the plugin's requirements
        return pslist.PsList.get_requirements() + []

    def list_injections(self, task):
        """Generate memory regions for a process that may contain
        injected code.
        """

        proc_layer_name = task.add_process_layer()
        if proc_layer_name == None:
            return

        proc_layer = self.context.memory[proc_layer_name]

        for vma in task.mm.mmap_iter:
            if vma.is_suspicious() and vma.get_name(task) != "[vdso]":    
                data = proc_layer.read(vma.vm_start, 64, pad = True) 
                yield vma, data

    def _generator(self, tasks):
        # determine if we're on a 32 or 64 bit kernel
        if self.context.symbol_space.get_type(self.config["vmlinux"] + constants.BANG + "pointer").size == 4:
            is_32bit_arch = True
        else:
            is_32bit_arch = False

        for task in tasks:
            process_name = utility.array_to_string(task.comm)

            for vma, data in self.list_injections(task):
                if is_32bit_arch:
                    architecture = "intel"
                else:
                    architecture = "intel64"

                disasm = interfaces_renderers.Disassembly(data, vma.vm_start, architecture)

                yield (0, (task.pid,
                           process_name,
                           format_hints.Hex(vma.vm_start),
                           format_hints.Hex(vma.vm_end),
                           vma.get_protection(),
                           format_hints.HexBytes(data),
                           disasm))

    def run(self):
        filter = pslist.PsList.create_filter([self.config.get('pid', None)])

        plugin = pslist.PsList.list_tasks

        return renderers.TreeGrid([("PID", int),
                                   ("Process", str),
                                   ("Start", format_hints.Hex),
                                   ("End", format_hints.Hex),
                                   ("Protection", str),
                                   ("Hexdump", format_hints.HexBytes),
                                   ("Disasm", interfaces_renderers.Disassembly)],
                                   self._generator(plugin(self.context, 
                                       self.config['primary'],
                                       self.config['vmlinux'],
                                       filter = filter)))

