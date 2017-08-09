import volatility.framework.interfaces.plugins as interfaces_plugins
import volatility.plugins.windows.pslist as pslist
from volatility.framework import exceptions, renderers
from volatility.framework.renderers import format_hints


class DllList(interfaces_plugins.PluginInterface):
    """Lists the loaded modules in a particular memory image"""

    @classmethod
    def get_requirements(cls):
        # Since we're calling the plugin, make sure we have the plugin's requirements
        return pslist.PsList.get_requirements() + []

    def _generator(self, procs):

        for proc in procs:

            for entry in proc.load_order_modules():

                BaseDllName = FullDllName = ""
                try:
                    BaseDllName = entry.BaseDllName.String
                    # We assume that if the BaseDllName points to an invalid buffer, so will FullDllName
                    FullDllName = entry.FullDllName.String
                except exceptions.InvalidAddressException:
                    pass

                yield (0, (proc.UniqueProcessId,
                           proc.ImageFileName.cast("string", max_length = proc.ImageFileName.vol.count,
                                                   errors = 'replace'),
                           format_hints.Hex(entry.DllBase), format_hints.Hex(entry.SizeOfImage),
                           BaseDllName, FullDllName))

    def run(self):

        plugin = pslist.PsList(self.context, "plugins.DllList")

        return renderers.TreeGrid([("PID", int),
                                   ("Process", str),
                                   ("Base", format_hints.Hex),
                                   ("Size", format_hints.Hex),
                                   ("Name", str),
                                   ("Path", str)],
                                  self._generator(plugin.list_processes()))
