# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl_v1.0
#

import logging

from volatility.framework import renderers
from volatility.framework.automagic import mac
from volatility.framework.configuration import requirements
from volatility.framework.interfaces import plugins
from volatility.plugins.mac import pslist

vollog = logging.getLogger(__name__)


class lsof(plugins.PluginInterface):
    """Lists all open file descriptors for all processes."""

    @classmethod
    def get_requirements(cls):
        return [
            requirements.TranslationLayerRequirement(
                name = 'primary', description = 'Kernel Address Space', architectures = ["Intel32", "Intel64"]),
            requirements.SymbolTableRequirement(name = "darwin", description = "Mac Kernel"),
            requirements.PluginRequirement(name = 'pslist', plugin = pslist.PsList, version = (1, 0, 0))
        ]

    def _generator(self, tasks):
        for task in tasks:
            pid = task.p_pid

            for _, filepath, fd in mac.MacUtilities.files_descriptors_for_process(self.config, self.context, task):
                if filepath and len(filepath) > 0:
                    yield (0, (pid, fd, filepath))

    def run(self):
        filter_func = pslist.PsList.create_pid_filter([self.config.get('pid', None)])

        return renderers.TreeGrid([("PID", int), ("File Descriptor", int), ("File Path", str)],
                                  self._generator(
                                      pslist.PsList.list_tasks(
                                          self.context,
                                          self.config['primary'],
                                          self.config['darwin'],
                                          filter_func = filter_func)))
