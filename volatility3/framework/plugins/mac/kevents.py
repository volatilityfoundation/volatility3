# This file is Copyright 2020 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

from typing import Iterable, Callable, Tuple

from volatility3.framework import renderers, interfaces, exceptions
from volatility3.framework.configuration import requirements
from volatility3.framework.objects import utility
from volatility3.framework.symbols import mac
from volatility3.plugins.mac import pslist


class Kevents(interfaces.plugins.PluginInterface):
    """Lists event handlers registered by processes"""

    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 0)

    event_types = {
        1: "EVFILT_READ",
        2: "EVFILT_WRITE",
        3: "EVFILT_AIO",
        4: "EVFILT_VNODE",
        5: "EVFILT_PROC",
        6: "EVFILT_SIGNAL",
        7: "EVFILT_TIMER",
        8: "EVFILT_MACHPORT",
        9: "EVFILT_FS",
        10: "EVFILT_USER",
        12: "EVFILT_VM",
    }

    vnode_filters = [
        ("NOTE_DELETE", 1),
        ("NOTE_WRITE", 2),
        ("NOTE_EXTEND", 4),
        ("NOTE_ATTRIB", 8),
        ("NOTE_LINK", 0x10),
        ("NOTE_RENAME", 0x20),
        ("NOTE_REVOKE", 0x40),
    ]

    proc_filters = [
        ("NOTE_EXIT", 0x80000000),
        ("NOTE_EXITSTATUS", 0x04000000),
        ("NOTE_FORK", 0x40000000),
        ("NOTE_EXEC", 0x20000000),
        ("NOTE_SIGNAL", 0x08000000),
        ("NOTE_REAP", 0x10000000),
    ]

    timer_filters = [
        ("NOTE_SECONDS", 1),
        ("NOTE_USECONDS", 2),
        ("NOTE_NSECONDS", 4),
        ("NOTE_ABSOLUTE", 8),
    ]

    all_filters = {
        4: vnode_filters,  # EVFILT_VNODE
        5: proc_filters,  # EVFILT_PROC
        7: timer_filters,  # EVFILT_TIMER
    }

    @classmethod
    def get_requirements(cls):
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Kernel module for the OS",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.PluginRequirement(
                name="pslist", plugin=pslist.PsList, version=(3, 0, 0)
            ),
            requirements.VersionRequirement(
                name="macutils", component=mac.MacUtilities, version=(1, 2, 0)
            ),
            requirements.ListRequirement(
                name="pid",
                description="Filter on specific process IDs",
                element_type=int,
                optional=True,
            ),
        ]

    def _parse_flags(self, filter_index, filter_flags):
        if filter_flags == 0 or filter_index not in self.all_filters:
            return ""

        context = []

        filters = self.all_filters[filter_index]
        for flag, index in filters:
            if filter_flags & index == index:
                context.append(flag)

        return ",".join(context)

    @classmethod
    def _walk_klist_array(cls, kernel, fdp, array_pointer_member, array_size_member):
        """
        Convenience wrapper for walking an array of lists of kernel events
        Handles invalid address references
        """
        try:
            klist_array_pointer = getattr(fdp, array_pointer_member)
            array_size = getattr(fdp, array_size_member)

            klist_array = kernel.object(
                object_type="array",
                offset=klist_array_pointer,
                count=array_size + 1,
                subtype=kernel.get_type("klist"),
            )

        except exceptions.InvalidAddressException:
            return None

        for klist in klist_array:
            for kn in mac.MacUtilities.walk_slist(klist, "kn_link"):
                yield kn

    @classmethod
    def _get_task_kevents(cls, kernel, task):
        """
        Enumerates event filters per task.
        Uses smear-safe APIs throughout as these data structures
        see a significant amount of smear
        """
        fdp = task.p_fd

        for kn in cls._walk_klist_array(kernel, fdp, "fd_knlist", "fd_knlistsize"):
            yield kn

        for kn in cls._walk_klist_array(kernel, fdp, "fd_knhash", "fd_knhashmask"):
            yield kn

        try:
            p_klist = task.p_klist
        except exceptions.InvalidAddressException:
            return None

        for kn in mac.MacUtilities.walk_slist(p_klist, "kn_link"):
            yield kn

    @classmethod
    def list_kernel_events(
        cls,
        context: interfaces.context.ContextInterface,
        kernel_module_name: str,
        filter_func: Callable[[int], bool] = lambda _: False,
    ) -> Iterable[
        Tuple[
            interfaces.objects.ObjectInterface,
            interfaces.objects.ObjectInterface,
            interfaces.objects.ObjectInterface,
        ]
    ]:
        """
        Returns the kernel event filters registered

        Return values:
            A tuple of 3 elements:
                1) The name of the process that registered the filter
                2) The process ID of the process that registered the filter
                3) The object of the associated kernel event filter
        """
        kernel = context.modules[kernel_module_name]

        list_tasks = pslist.PsList.get_list_tasks(pslist.PsList.pslist_methods[0])

        for task in list_tasks(context, kernel_module_name, filter_func):
            task_name = utility.array_to_string(task.p_comm)
            pid = task.p_pid

            for kn in cls._get_task_kevents(kernel, task):
                yield task_name, pid, kn

    def _generator(self):
        filter_func = pslist.PsList.create_pid_filter(self.config.get("pid", None))

        for task_name, pid, kn in self.list_kernel_events(
            self.context, self.config["kernel"], filter_func=filter_func
        ):
            if hasattr(kn.kn_kevent, "filter"):
                filter = kn.kn_kevent.filter
            elif hasattr(kn.kn_kevent, "kei_filter"):
                filter = kn.kn_kevent.kei_filter
            filter_index = filter * -1
            if filter_index in self.event_types:
                filter_name = self.event_types[filter_index]
            else:
                continue

            try:
                if hasattr(kn.kn_kevent, "ident"):
                    ident = kn.kn_kevent.ident
                elif hasattr(kn.kn_kevent, "kei_ident"):
                    ident = kn.kn_kevent.kei_ident
            except exceptions.InvalidAddressException:
                continue

            if hasattr(kn, "kn_sfflags"):
                sfflags = kn.kn_sfflags
            elif hasattr(kn.kn_kevent, "kei_sfflags"):
                sfflags = kn.kn_kevent.kei_sfflags
            context = self._parse_flags(filter_index, sfflags)

            yield (0, (pid, task_name, ident, filter_name, context))

    def run(self):
        return renderers.TreeGrid(
            [
                ("PID", int),
                ("Process", str),
                ("Ident", int),
                ("Filter", str),
                ("Context", str),
            ],
            self._generator(),
        )
