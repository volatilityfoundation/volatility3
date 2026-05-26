# This file is Copyright 2020 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

from volatility3.framework import renderers, interfaces, exceptions
from volatility3.framework.configuration import requirements
from volatility3.framework.objects import utility


class VFSevents(interfaces.plugins.PluginInterface):
    """Lists processes that are filtering file system events"""

    _required_framework_version = (2, 0, 0)

    event_types = [
        "CREATE_FILE",
        "DELETE",
        "STAT_CHANGED",
        "RENAME",
        "CONTENT_MODIFIED",
        "EXCHANGE",
        "FINDER_INFO_CHANGED",
        "CREATE_DIR",
        "CHOWN",
        "XATTR_MODIFIED",
        "XATTR_REMOVED",
        "DOCID_CREATED",
        "DOCID_CHANGED",
    ]

    @classmethod
    def get_requirements(cls):
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Kernel module for the OS",
                architectures=["Intel32", "Intel64"],
            ),
        ]

    def _generator(self):
        """
        Lists the registered VFS event watching processes
        Also lists which event(s) a process is registered for
        """

        kernel = self.context.modules[self.config["kernel"]]

        watcher_table = kernel.object_from_symbol("watcher_table")

        for watcher in watcher_table:
            if watcher == 0:
                continue

            task_name = utility.array_to_string(watcher.proc_name)
            task_pid = watcher.pid

            events = []

            try:
                event_array = kernel.object(
                    object_type="array",
                    offset=watcher.event_list,
                    absolute=True,
                    count=13,
                    subtype=kernel.get_type("unsigned char"),
                )

            except exceptions.InvalidAddressException:
                continue

            for i, event in enumerate(event_array):
                if event == 1:
                    events.append(self.event_types[i])

            if events != []:
                yield (0, (task_name, task_pid, ",".join(events)))

    def run(self):
        return renderers.TreeGrid(
            [("Name", str), ("PID", int), ("Events", str)], self._generator()
        )
