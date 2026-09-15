# This file is Copyright 2022 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

import struct
from typing import List

from volatility3.framework import constants, renderers, symbols, exceptions, interfaces
from volatility3.framework.configuration import requirements
from volatility3.framework.interfaces import plugins
from volatility3.framework.objects import utility
from volatility3.framework.symbols.linux.hash import HashIntermedSymbols
from volatility3.plugins.linux import pslist

class Var(plugins.PluginInterface):
    """Recovers a process' dynamic environment variables."""
    shells = ("/bin/bash", "/bin/dash", "/bin/sh")

    _required_framework_version = (2, 0, 0)

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
            requirements.ListRequirement(
                name="pid",
                element_type=int,
                description="Process IDs to include (all other processes are excluded)",
                optional=True,
            ),
        ]

    def _generator(self, tasks):
        for task in tasks:
            proc_layer_name = task.add_process_layer()
            if not proc_layer_name:
                yield (0, (task.pid, utility.array_to_string(task.comm), ""))
                continue
            varstr = ""
            for (key, val) in self.bash_environment(
                task, proc_layer_name, self.context, self.config["kernel"]
            ):
                if key or val:
                    varstr = f"{varstr}{key}={val} "

            yield (0, (task.pid, utility.array_to_string(task.comm), varstr))

    def bash_environment(self, task, proc_layer_name, context, module):
        for (key, val) in self.dynamic_env(task, proc_layer_name, context, module):
            yield (key, val)

        for (key, val) in self.shell_variables(
            task, proc_layer_name, context, module
        ):
            yield (key, val)

    def dynamic_env(self, task, proc_layer_name, context, module):
        symbol_table_name = context.modules[module].symbol_table_name
        is_32bit = not symbols.symbol_table_is_64bit(
            context, symbol_table_name
        )
        addr_sz = 8
        pack_format = "Q"
        if is_32bit:
            addr_sz = 4
            pack_format = "I"
        proc_layer = context.layers[proc_layer_name]
        addr_cache = {0}
        for vma in task.mm.get_mmap_iter():
            if not (vma.vm_file and vma.get_protection() == "rw-"):
                continue
            fname = vma.get_name(context, task)
            if fname.find("ld") == -1 and (
                not fname.endswith(self.shells)
            ):
                continue
            env_start = 0
            if not isinstance(vma.vm_start, int) or not isinstance(vma.vm_end, int):
                continue
            vma_start = vma.vm_start
            vma_end = vma.vm_end
            vma_len = vma_end - vma_start
            vma_data = proc_layer.read(vma_start, vma_len, pad=True)
            for off in range(0, vma_len - addr_sz, addr_sz):
                addrstr = vma_data[off : off + addr_sz]
                addr, = struct.unpack(pack_format, addrstr)

                if addr in addr_cache:
                    continue
                addr_cache.add(addr)
                if addr:
                    firstaddrstr = proc_layer.read(addr, addr_sz, pad=True)
                    firstaddr, = struct.unpack(pack_format, firstaddrstr)
                    buf = proc_layer.read(firstaddr, 64, pad=True)
                    eqidx = buf.find(b"=")
                    if eqidx > 0:
                        nullidx = buf.find(b"\x00")
                        if nullidx >= eqidx:
                            env_start = addr

            if env_start == 0:
                continue
            envars = context.object(
                symbol_table_name + constants.BANG + "array",
                layer_name=proc_layer_name,
                offset=env_start,
                subtype=context.symbol_space.get_type(
                    symbol_table_name + constants.BANG + "pointer"
                ),
                count=256,
            )
            for var in envars:
                if var:
                    sizes = [8, 16, 32, 64, 128, 256, 384, 512, 1024, 2048, 4096]
                    good_varstr = None
                    for size in sizes:
                        try:
                            varstr = proc_layer.read(var, size)
                        except exceptions.InvalidAddressException:
                            continue
                        if not varstr:
                            continue
                        eqidx = varstr.find(b"=")
                        idx = varstr.find(b"\x00")
                        if idx == -1 or eqidx == -1 or idx < eqidx:
                            continue
                        good_varstr = varstr
                        break
                    if good_varstr:
                        try:
                            good_varstr = str(good_varstr[:idx], "utf-8")
                            key = good_varstr[:eqidx]
                            val = good_varstr[eqidx + 1 :]
                            yield (key, val)
                        except exceptions.InvalidAddressException:
                            continue
                        except UnicodeDecodeError:
                            continue
                    else:
                        break

    def shell_variables(self, task, proc_layer_name, context, module):
        symbol_table_name = context.modules[module].symbol_table_name
        proc_layer = context.layers[proc_layer_name]
        is_32bit = not symbols.symbol_table_is_64bit(
            context, symbol_table_name
        )
        addr_sz = 8
        pack_format = "Q"
        hash_json_file = "hash64"
        if is_32bit:
            addr_sz = 4
            pack_format = "I"
            hash_json_file = "hash32"
        ptr_cache = {0}
        bash_was_last = False
        for vma in task.mm.get_mmap_iter():
            try:
                if vma.vm_file:
                    fname = vma.get_name(context, task)
                    bash_was_last = fname.endswith(self.shells)

                if vma.vm_file or vma.get_protection() != "rw-":
                    continue
            except exceptions.InvalidAddressException:
                continue
            if bash_was_last == False:
                continue
            if not isinstance(vma.vm_start, int) or not isinstance(vma.vm_end, int):
                continue
            vma_start = vma.vm_start
            vma_end = vma.vm_end
            vma_len = vma_end - vma_start
            vma_data = proc_layer.read(vma_start, vma_len, pad=True)
            for off in range(0, vma_len - addr_sz, addr_sz):
                ptr_test = vma_data[off : off + addr_sz]
                ptr, = struct.unpack(pack_format, ptr_test)
                if ptr in ptr_cache:
                    continue
                try:
                    ptr_cache.add(ptr)
                    ptr_test2 = proc_layer.read(ptr + 20, addr_sz)
                    if not ptr_test2:
                        continue
                except exceptions.InvalidAddressException:
                    continue
                ptr2, = struct.unpack(pack_format, ptr_test2)
                try:
                    test = proc_layer.read(ptr2 + addr_sz, 4)
                except exceptions.InvalidAddressException:
                    continue
                # this searches for bash_hash_table.nbuckets
                if not test or test != b"\x40\x00\x00\x00":
                    continue
                try:
                    hash_table_name = HashIntermedSymbols.create(
                        context, self.config_path, "linux", hash_json_file
                    )
                    htable = context.object(
                        hash_table_name + constants.BANG + "bash_hash_table",
                        layer_name=proc_layer_name,
                        offset=ptr2,
                    )
                    for ent in htable:
                        key = utility.array_to_string(ent.key.dereference())
                        val = utility.array_to_string(ent.data.value.dereference())
                        yield (key, val)
                except exceptions.InvalidAddressException:
                    continue
            bash_was_last = False

    def run(self):
        filter_func = pslist.PsList.create_pid_filter(self.config.get("pid", None))

        return renderers.TreeGrid(
            [("PID", int), ("Process", str), ("Vars", str)],
            self._generator(
                pslist.PsList.list_tasks(
                    self.context, self.config["kernel"], filter_func=filter_func
                )
            ),
        )