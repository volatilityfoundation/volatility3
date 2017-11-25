import volatility.framework.interfaces.plugins as interfaces_plugins
from volatility.framework import exceptions, renderers
from volatility.framework.renderers import format_hints
from volatility.plugins.windows import pslist


class DllList(interfaces_plugins.PluginInterface):
    """Lists the loaded modules in a particular windows memory image"""

    @classmethod
    def get_requirements(cls):
        # Since we're calling the plugin, make sure we have the plugin's requirements
        return pslist.PsList.get_requirements() + []

    def _generator(self, procs):

        for proc in procs:

            for entry in proc.load_order_modules():

                BaseDllName = FullDllName = ""
                try:
                    BaseDllName = entry.BaseDllName.helper_string
                    # We assume that if the BaseDllName points to an invalid buffer, so will FullDllName
                    FullDllName = entry.FullDllName.helper_string
                except exceptions.InvalidAddressException:
                    pass

                yield (0, (proc.UniqueProcessId,
                           proc.ImageFileName.cast("string", max_length = proc.ImageFileName.vol.count,
                                                   errors = 'replace'),
                           format_hints.Hex(entry.DllBase), format_hints.Hex(entry.SizeOfImage),
                           BaseDllName, FullDllName))

    def run(self):

        plugin = pslist.PsList(self.context, self.config_path)

        return renderers.TreeGrid([("PID", int),
                                   ("Process", str),
                                   ("Base", format_hints.Hex),
                                   ("Size", format_hints.Hex),
                                   ("Name", str),
                                   ("Path", str)],
                                  self._generator(plugin.list_processes()))
