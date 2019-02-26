import logging

from volatility.framework import exceptions, renderers
from volatility.framework.automagic import mac
from volatility.framework.interfaces import plugins
from volatility.framework.configuration import requirements
from volatility.framework.objects import utility
from volatility.framework.renderers import format_hints
from volatility.plugins.mac import pslist

vollog = logging.getLogger(__name__)

class Netstat(plugins.PluginInterface):
    """Lists all network connections for all processes"""

    @classmethod
    def get_requirements(cls):
        return [requirements.TranslationLayerRequirement(name = 'primary',
                                                         description = 'Kernel Address Space',
                                                         architectures = ["Intel32", "Intel64"]),
                requirements.SymbolRequirement(name = "darwin",
                                               description = "Mac Kernel")]

    def _generator(self, tasks):
        for task in tasks:
            task_name = utility.array_to_string(task.p_comm)
            pid = int(task.p_pid)

            for filp, _, _ in mac.MacUtilities.files_descriptors_for_process(self.config, self.context,
                                                                                           task):
                try:
                    ftype = filp.f_fglob.get_fg_type()
                except exceptions.PagedInvalidAddressException:
                    continue
               
                if ftype != 'DTYPE_SOCKET':
                    continue
               
                try:
                    socket = filp.f_fglob.fg_data.dereference().cast("socket") 
                except exceptions.PagedInvalidAddressException:
                    continue
 
                family = int(socket.get_family())

                if family == 1:
                    try:
                        upcb = socket.so_pcb.dereference().cast("unpcb")
                        path = utility.array_to_string(upcb.unp_addr.sun_path)
                    except exceptions.PagedInvalidAddressException:
                        continue

                    yield (0, (format_hints.Hex(socket.vol.offset), 
                              "UNIX", 
                              path, 
                              0, 
                              "", 
                              0, 
                              "",
                              "{}/{:d}".format(task_name, pid)))

                elif family in [2, 30]:
                    state = socket.get_state()
                    proto = socket.get_protocol_as_string()

                    vals = socket.get_converted_connection_info()

                    if vals:
                        (lip, lport, rip, rport) =  vals
     
                        yield (0, (format_hints.Hex(socket.vol.offset), 
                                   proto, 
                                   lip, 
                                   lport, 
                                   rip, 
                                   rport, 
                                   state,
                                   "{}/{:d}".format(task_name, pid)))

    def run(self):
        #mac.MacUtilities.aslr_mask_symbol_table(self.config, self.context)

        filter = pslist.PsList.create_filter([self.config.get('pid', None)])

        plugin = pslist.PsList.list_tasks

        return renderers.TreeGrid(
            [("Offset", format_hints.Hex),
             ("Proto", str),
             ("Local IP", str),
             ("Local Port", int),
             ("Remote IP", str),
             ("Remote Port", int),
             ("State", str),
             ("Process", str)],
            self._generator(plugin(self.context,
                                   self.config['primary'],
                                   self.config['darwin'],
                                   filter = filter)))
