# This file is Copyright 2024 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

import logging
from typing import List

from volatility3.framework import renderers, interfaces, constants
from volatility3.framework.symbols import linux
from volatility3.framework.renderers import format_hints
from volatility3.framework.interfaces import plugins
from volatility3.framework.configuration import requirements
from volatility3.plugins.linux import pslist

vollog = logging.getLogger(__name__)


class PIDHashTable(plugins.PluginInterface):
    """Enumerates processes through the PID hash table"""

    _required_framework_version = (2, 0, 0)

    _version = (1, 0, 1)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Linux kernel",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.PluginRequirement(
                name="pslist", plugin=pslist.PsList, version=(2, 0, 0)
            ),
            requirements.VersionRequirement(
                name="linuxutils", component=linux.LinuxUtilities, version=(2, 1, 0)
            ),
            requirements.BooleanRequirement(
                name="decorate_comm",
                description="Show `user threads` comm in curly brackets, and `kernel threads` comm in square brackets",
                optional=True,
                default=False,
            ),
        ]

    def _is_valid_task(self, task) -> bool:
        return bool(task and task.pid > 0 and task.parent)

    def _get_pidtype_pid(self):
        vmlinux = self.context.modules[self.config["kernel"]]

        # The pid_type enumeration is present since 2.5.37, just in case
        pid_type_enum = vmlinux.get_enumeration("pid_type")
        if not pid_type_enum:
            vollog.error("Cannot find pid_type enum. Unsupported kernel")
            return None

        pidtype_pid = pid_type_enum.choices.get("PIDTYPE_PID")
        if pidtype_pid is None:
            vollog.error("Cannot find PIDTYPE_PID. Unsupported kernel")
            return None

        # Typically PIDTYPE_PID = 0
        return pidtype_pid

    def _get_pidhash_array(self):
        vmlinux = self.context.modules[self.config["kernel"]]

        pidhash_shift = vmlinux.object_from_symbol("pidhash_shift")
        pidhash_size = 1 << pidhash_shift

        array_type_name = vmlinux.symbol_table_name + constants.BANG + "array"

        pidhash_ptr = vmlinux.object_from_symbol("pid_hash")
        # pidhash is an array of hlist_heads
        pidhash = self._context.object(
            array_type_name,
            offset=pidhash_ptr,
            subtype=vmlinux.get_type("hlist_head"),
            count=pidhash_size,
            layer_name=vmlinux.layer_name,
        )

        return pidhash

    def _walk_upid(self, seen_upids, upid):
        vmlinux = self.context.modules[self.config["kernel"]]

        while upid:
            if upid.vol.offset in seen_upids:
                break
            seen_upids.add(upid.vol.offset)

            pid_chain = upid.pid_chain
            if not pid_chain:
                break

            upid = linux.LinuxUtilities.container_of(
                pid_chain.next, "upid", "pid_chain", vmlinux
            )

    def _get_upids(self):
        vmlinux = self.context.modules[self.config["kernel"]]

        # 2.6.24 <= kernels < 4.15
        pidhash = self._get_pidhash_array()

        seen_upids = set()
        for hlist in pidhash:
            # each entry in the hlist is a upid which is wrapped in a pid
            ent = hlist.first

            while ent:
                # upid->pid_chain exists 2.6.24 <= kernel < 4.15
                upid = linux.LinuxUtilities.container_of(
                    ent.vol.offset, "upid", "pid_chain", vmlinux
                )

                if upid.vol.offset in seen_upids:
                    break

                self._walk_upid(seen_upids, upid)

                ent = ent.next

        return seen_upids

    def _pid_hash_implementation(self):
        vmlinux = self.context.modules[self.config["kernel"]]

        # 2.6.24 <= kernels < 4.15
        task_pids_off = vmlinux.get_type("task_struct").relative_child_offset("pids")
        pidtype_pid = self._get_pidtype_pid()

        for upid in self._get_upids():
            pid = linux.LinuxUtilities.container_of(upid, "pid", "numbers", vmlinux)
            if not pid:
                continue

            pid_tasks_0 = pid.tasks[pidtype_pid].first
            if not pid_tasks_0:
                continue

            task = vmlinux.object(
                "task_struct", offset=pid_tasks_0 - task_pids_off, absolute=True
            )
            if self._is_valid_task(task):
                yield task

    def _task_for_radix_pid_node(self, nodep):
        vmlinux = self.context.modules[self.config["kernel"]]

        # kernels >= 4.15
        pid = vmlinux.object("pid", offset=nodep, absolute=True)
        pidtype_pid = self._get_pidtype_pid()

        pid_tasks_0 = pid.tasks[pidtype_pid].first
        if not pid_tasks_0:
            return None

        task_struct_type = vmlinux.get_type("task_struct")
        if task_struct_type.has_member("pids"):
            member = "pids"
        elif task_struct_type.has_member("pid_links"):
            member = "pid_links"
        else:
            return None

        task_pids_off = task_struct_type.relative_child_offset(member)
        task = vmlinux.object(
            "task_struct", offset=pid_tasks_0 - task_pids_off, absolute=True
        )
        return task

    def _pid_namespace_idr(self):
        vmlinux = self.context.modules[self.config["kernel"]]

        # kernels >= 4.15
        ns_addr = vmlinux.get_symbol("init_pid_ns").address
        ns = vmlinux.object("pid_namespace", offset=ns_addr)

        for page_addr in ns.idr.get_entries():
            task = self._task_for_radix_pid_node(page_addr)
            if self._is_valid_task(task):
                yield task

    def _determine_pid_func(self):
        vmlinux = self.context.modules[self.config["kernel"]]

        pid_hash = vmlinux.has_symbol("pid_hash") and vmlinux.has_symbol(
            "pidhash_shift"
        )  # 2.5.55 <= kernels < 4.15

        has_pid_numbers = vmlinux.has_type("pid") and vmlinux.get_type(
            "pid"
        ).has_member(
            "numbers"
        )  # kernels >= 2.6.24

        has_pid_chain = vmlinux.has_type("upid") and vmlinux.get_type(
            "upid"
        ).has_member(
            "pid_chain"
        )  # 2.6.24 <= kernels < 4.15

        # kernels >= 4.15
        pid_idr = vmlinux.has_type("pid_namespace") and vmlinux.get_type(
            "pid_namespace"
        ).has_member("idr")

        if pid_idr:
            # kernels >= 4.15
            return self._pid_namespace_idr
        elif pid_hash and has_pid_numbers and has_pid_numbers and has_pid_chain:
            # 2.6.24 <= kernels < 4.15
            return self._pid_hash_implementation

        return None

    def get_tasks(self) -> interfaces.objects.ObjectInterface:
        """Enumerates processes through the PID hash table

        Yields:
            task_struct objects
        """
        pid_func = self._determine_pid_func()
        if not pid_func:
            vollog.error("Cannot determine which PID hash table this kernel is using")
            return

        yield from sorted(pid_func(), key=lambda t: (t.tgid, t.pid))

    def _generator(
        self, decorate_comm: bool = False
    ) -> interfaces.objects.ObjectInterface:
        for task in self.get_tasks():
            offset, pid, tid, ppid, name = pslist.PsList.get_task_fields(
                task, decorate_comm
            )
            fields = format_hints.Hex(offset), pid, tid, ppid, name
            yield 0, fields

    def run(self):
        decorate_comm = self.config.get("decorate_comm")

        headers = [
            ("OFFSET", format_hints.Hex),
            ("PID", int),
            ("TID", int),
            ("PPID", int),
            ("COMM", str),
        ]
        return renderers.TreeGrid(headers, self._generator(decorate_comm=decorate_comm))
