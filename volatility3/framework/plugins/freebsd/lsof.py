# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

import logging

from volatility3.framework import renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.interfaces import plugins
from volatility3.framework.symbols import freebsd
from volatility3.plugins.freebsd import pslist

vollog = logging.getLogger(__name__)


class Lsof(plugins.PluginInterface):
    """Lists all open file descriptors for all processes."""

    _required_framework_version = (2, 0, 0)

    @classmethod
    def get_requirements(cls):
        return [
            requirements.ModuleRequirement(
                name = "kernel",
                description = "Kernel module for the OS",
                architectures = ["Intel32", "Intel64"],
            ),
            requirements.VersionRequirement(name = "freebsdutils",
                                            component = freebsd.FreebsdUtilities,
                                            version = (1, 0, 0)),
            requirements.PluginRequirement(name = "pslist", plugin = pslist.PsList, version = (1, 0, 0)),
            requirements.ListRequirement(
                name = "pid",
                description = "Filter on specific process IDs",
                element_type = int,
                optional = True,
            ),
        ]

    def _generator(self, tasks):
        kernel = self.context.modules[self.config["kernel"]]
        for task in tasks:
            pid = task.p_pid

            for _, filepath, fd in freebsd.FreebsdUtilities.files_descriptors_for_process(self.context, kernel, task):
                yield (0, (pid, fd, filepath))

    def run(self):
        filter_func = pslist.PsList.create_pid_filter(self.config.get("pid", None))

        return renderers.TreeGrid(
            [("PID", int), ("File Descriptor", int), ("File Path", str)],
            self._generator(pslist.PsList.list_tasks(self.context, self.config["kernel"], filter_func = filter_func)),
        )
