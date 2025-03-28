# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

import abc
import collections.abc
import logging
import functools
import binascii
import stat
import datetime
import uuid
from typing import (
    Generator,
    Iterable,
    Iterator,
    Optional,
    Tuple,
    List,
    Union,
    Dict,
    Callable,
)

from volatility3.framework import constants, exceptions, objects, interfaces, symbols
from volatility3.framework.renderers import conversion
from volatility3.framework.constants import linux as linux_constants
from volatility3.framework.layers import linear, intel
from volatility3.framework.objects import utility
from volatility3.framework.symbols import generic, linux, intermed
from volatility3.framework.symbols.linux.extensions import elf

vollog = logging.getLogger(__name__)

# Keep these in a basic module, to prevent import cycles when symbol providers require them


class module(generic.GenericIntelProcess):

    def is_valid(self):
        """Determine whether it is a valid module object by verifying the self-referential
        in module_kobject. This also confirms that the module is actively allocated and
        not a remnant of freed memory or a failed module load attempt by verifying the
        module memory section sizes.
        """
        layer = self._context.layers[self.vol.layer_name]
        # Make sure the entire module content is readable
        if not layer.is_valid(self.vol.offset, self.vol.size):
            return False

        core_size = self.get_core_size()
        core_text_size = self.get_core_text_size()
        init_size = self.get_init_size()
        if not (
            0 < core_text_size <= linux_constants.MODULE_MAXIMUM_CORE_TEXT_SIZE
            and 0 < core_size <= linux_constants.MODULE_MAXIMUM_CORE_SIZE
            and core_size + init_size >= linux_constants.MODULE_MINIMUM_SIZE
        ):
            return False

        if not (
            self.mkobj
            and self.mkobj.mod
            and self.mkobj.mod.is_readable()
            and self.mkobj.mod == self.vol.offset
        ):
            return False

        return True

    @functools.cached_property
    def mod_mem_type(self) -> Dict:
        """Return the mod_mem_type enum choices if available or an empty dict if not"""
        # mod_mem_type and module_memory were added in kernel 6.4 which replaces
        # module_layout for storing the information around core_layout etc.
        # see commit ac3b43283923440900b4f36ca5f9f0b1ca43b70e for more information
        symbol_table_name = self.get_symbol_table_name()
        mod_mem_type_symname = symbol_table_name + constants.BANG + "mod_mem_type"
        symbol_space = self._context.symbol_space
        try:
            mod_mem_type = symbol_space.get_enumeration(mod_mem_type_symname).choices
        except exceptions.SymbolError:
            mod_mem_type = {}
            vollog.debug(
                "Unable to find mod_mem_type enum. This message can be ignored for kernels < 6.4"
            )

        return mod_mem_type

    def _get_mem_type(self, mod_mem_type_name):
        module_mem_index = self.mod_mem_type.get(mod_mem_type_name)
        if module_mem_index is None:
            raise AttributeError(f"Unknown module memory type '{mod_mem_type_name}'")

        if not (0 <= module_mem_index < self.mem.count):
            raise AttributeError(
                f"Invalid module memory type index '{module_mem_index}'"
            )

        return self.mem[module_mem_index]

    def _get_mem_size(self, mod_mem_type_name) -> int:
        return self._get_mem_type(mod_mem_type_name).size

    def _get_mem_base(self, mod_mem_type_name) -> int:
        return self._get_mem_type(mod_mem_type_name).base

    def get_module_base(self) -> int:
        if self.has_member("mem"):  # kernels 6.4+
            return self._get_mem_base("MOD_TEXT")
        elif self.has_member("core_layout"):
            return self.core_layout.base
        elif self.has_member("module_core"):
            return self.module_core

        raise AttributeError("Unable to get module base")

    def get_init_size(self) -> int:
        if self.has_member("mem"):  # kernels 6.4+
            return (
                self._get_mem_size("MOD_INIT_TEXT")
                + self._get_mem_size("MOD_INIT_DATA")
                + self._get_mem_size("MOD_INIT_RODATA")
            )
        elif self.has_member("init_layout"):
            return self.init_layout.size
        elif self.has_member("init_size"):
            return self.init_size

        raise AttributeError("Unable to determine .init section size of module")

    def get_core_size(self) -> int:
        if self.has_member("mem"):  # kernels 6.4+
            return (
                self._get_mem_size("MOD_TEXT")
                + self._get_mem_size("MOD_DATA")
                + self._get_mem_size("MOD_RODATA")
                + self._get_mem_size("MOD_RO_AFTER_INIT")
            )
        elif self.has_member("core_layout"):
            return self.core_layout.size
        elif self.has_member("core_size"):
            return self.core_size

        raise AttributeError("Unable to determine core size of module")

    def get_core_text_size(self) -> int:
        if self.has_member("mem"):  # kernels 6.4+
            return self._get_mem_size("MOD_TEXT")
        elif self.has_member("core_layout"):
            return self.core_layout.text_size
        elif self.has_member("core_text_size"):
            return self.core_text_size

        raise AttributeError("Unable to determine core text size of module")

    def get_module_core(self) -> objects.Pointer:
        if self.has_member("mem"):  # kernels 6.4+
            return self._get_mem_base("MOD_TEXT")
        elif self.has_member("core_layout"):
            return self.core_layout.base
        elif self.has_member("module_core"):
            return self.module_core
        raise AttributeError("Unable to get module core")

    def get_module_init(self) -> objects.Pointer:
        if self.has_member("mem"):  # kernels 6.4+
            return self._get_mem_base("MOD_INIT_TEXT")
        elif self.has_member("init_layout"):
            return self.init_layout.base
        elif self.has_member("module_init"):
            return self.module_init
        raise AttributeError("Unable to get module init")

    def get_name(self) -> Optional[str]:
        """Get the name of the module as a string"""
        try:
            return utility.array_to_string(self.name)
        except exceptions.InvalidAddressException:
            return None

    def _get_sect_count(self, grp: interfaces.objects.ObjectInterface) -> int:
        """Try to determine the number of valid sections"""
        symbol_table_name = self.get_symbol_table_name()
        arr = self._context.object(
            symbol_table_name + constants.BANG + "array",
            layer_name=self.vol.layer_name,
            offset=grp.attrs,
            subtype=self._context.symbol_space.get_type(
                symbol_table_name + constants.BANG + "pointer"
            ),
            count=25,
        )

        idx = 0
        while arr[idx] and arr[idx].is_readable():
            idx = idx + 1
        return idx

    @functools.cached_property
    def number_of_sections(self) -> int:
        if self.sect_attrs.has_member("nsections"):
            return self.sect_attrs.nsections

        return self._get_sect_count(self.sect_attrs.grp)

    def get_sections(self) -> Iterable[interfaces.objects.ObjectInterface]:
        """Get a list of section attributes for the given module."""

        symbol_table_name = self.get_symbol_table_name()
        arr = self._context.object(
            symbol_table_name + constants.BANG + "array",
            layer_name=self.vol.layer_name,
            offset=self.sect_attrs.attrs.vol.offset,
            subtype=self._context.symbol_space.get_type(
                symbol_table_name + constants.BANG + "module_sect_attr"
            ),
            count=self.number_of_sections,
        )

        yield from arr

    def get_elf_table_name(self):
        elf_table_name = intermed.IntermediateSymbolTable.create(
            self._context,
            "elf_symbol_table",
            "linux",
            "elf",
            native_types=None,
            class_types=elf.class_types,
        )
        return elf_table_name

    def get_symbols(self) -> Iterable[interfaces.objects.ObjectInterface]:
        """Get ELF symbol objects for this module"""

        if not self.section_strtab or self.num_symtab < 1:
            return None

        elf_table_name = self.get_elf_table_name()
        symbol_table_name = self.get_symbol_table_name()

        is_64bit = symbols.symbol_table_is_64bit(
            context=self._context, symbol_table_name=symbol_table_name
        )
        sym_name = "Elf64_Sym" if is_64bit else "Elf32_Sym"
        sym_type = self._context.symbol_space.get_type(
            elf_table_name + constants.BANG + sym_name
        )
        elf_syms = self._context.object(
            symbol_table_name + constants.BANG + "array",
            layer_name=self.vol.layer_name,
            offset=self.section_symtab,
            subtype=sym_type,
            count=self.num_symtab,
        )
        for elf_sym_obj in elf_syms:
            # Prepare the symbol object for methods like get_name()
            elf_sym_obj.cached_strtab = self.section_strtab
            yield elf_sym_obj

    def get_symbols_names_and_addresses(
        self, max_symbols: int = 4096
    ) -> Iterable[Tuple[str, int]]:
        """Get names and addresses for each symbol of the module

        Yields:
                A tuple for each symbol containing the symbol name and its corresponding value
        """
        layer = self._context.layers[self.vol.layer_name]
        for iteration_counter, elf_sym_obj in enumerate(self.get_symbols()):
            if iteration_counter > max_symbols:
                vollog.debug(
                    f"Hit maximum symbols ({max_symbols}) for ELF at {self.vol.offset:#x} in layer {self.vol.layer_name}"
                )
                return

            sym_name = elf_sym_obj.get_name()
            if not sym_name:
                continue

                # Normalize sym.st_value offset, which is an address pointing to the symbol value
            sym_address = elf_sym_obj.st_value & layer.address_mask
            yield (sym_name, sym_address)

    @functools.lru_cache
    def get_module_address_boundaries(self) -> Optional[Tuple[int, int]]:
        """Return the module address boundaries based on its symbol addresses"""

        if not self.section_strtab or self.num_symtab < 1:
            return None

        elf_table_name = self.get_elf_table_name()
        symbol_table_name = self.get_symbol_table_name()

        is_64bit = symbols.symbol_table_is_64bit(
            context=self._context, symbol_table_name=symbol_table_name
        )
        sym_name = "Elf64_Sym" if is_64bit else "Elf32_Sym"
        sym_type = self._context.symbol_space.get_type(
            elf_table_name + constants.BANG + sym_name
        )
        elf_syms = self._context.object(
            symbol_table_name + constants.BANG + "array",
            layer_name=self.vol.layer_name,
            offset=self.section_symtab,
            subtype=sym_type,
            count=self.num_symtab,
        )
        # They should be sorted, but just in case
        elf_syms_sorted = sorted(elf_syms, key=lambda x: x.st_value)

        layer = self._context.layers[self.vol.layer_name]

        # The first elf_sym is null
        first_symbol = elf_syms_sorted[1]
        last_symbol = elf_syms_sorted[-1]
        minimum_address = first_symbol.st_value & layer.address_mask
        maximum_address = (
            last_symbol.st_value & layer.address_mask + last_symbol.st_size
        )

        return minimum_address, maximum_address

    def get_symbol(self, wanted_sym_name) -> Optional[int]:
        """Get symbol address for a given symbol name"""
        for sym_name, sym_address in self.get_symbols_names_and_addresses():
            if wanted_sym_name == sym_name:
                return sym_address

        return None

    def get_symbol_by_address(self, wanted_sym_address) -> Optional[str]:
        """Get symbol name for a given symbol address"""
        for sym_name, sym_address in self.get_symbols_names_and_addresses():
            if wanted_sym_address == sym_address:
                return sym_name

        return None

    @property
    def section_symtab(self) -> Optional[interfaces.objects.ObjectInterface]:
        try:
            if self.has_member("kallsyms"):
                return self.kallsyms.symtab
            elif self.has_member("symtab"):
                return self.symtab
        except exceptions.InvalidAddressException:
            vollog.debug(
                f"Page fault encountered when accessing symtab of ELF at {self.vol.offset:#x} in {self.vol.layer_name}"
            )
            return None

        raise AttributeError("Unable to get symtab")

    @property
    def num_symtab(self) -> Optional[int]:
        try:
            if self.has_member("kallsyms"):
                return int(self.kallsyms.num_symtab)
            elif self.has_member("num_symtab"):
                return int(self.member("num_symtab"))
        except exceptions.InvalidAddressException:
            vollog.debug(
                f"Page fault encountered when accessing num_symtab of ELF at {self.vol.offset:#x} in {self.vol.layer_name}"
            )
            return None

        raise AttributeError("Unable to determine number of symbols")

    @property
    def section_strtab(self) -> Optional[interfaces.objects.ObjectInterface]:
        try:
            # Newer kernels
            if self.has_member("kallsyms"):
                return self.kallsyms.strtab
            # Older kernels
            elif self.has_member("strtab"):
                return self.strtab
        except exceptions.InvalidAddressException:
            vollog.debug(
                f"Page fault encountered when accessing strtab of ELF at {self.vol.offset:#x} in {self.vol.layer_name}"
            )
            return None

        raise AttributeError("Unable to get strtab")

    @property
    def section_typetab(self) -> Optional[interfaces.objects.ObjectInterface]:
        try:
            if self.has_member("kallsyms") and self.kallsyms.has_member("typetab"):
                # kernels >= 4.5 8244062ef1e54502ef55f54cced659913f244c3e: kallsyms was added
                # kernels >= 5.2 1c7651f43777cdd59c1aaa82c87324d3e7438c7b: types have its own array
                return self.kallsyms.typetab
        except exceptions.InvalidAddressException:
            vollog.debug(
                f"Page fault encountered when accessing typetab of ELF at {self.vol.offset:#x} in {self.vol.layer_name}"
            )
            return None

        raise AttributeError("Unable to get typetab section, it needs a kernel >= 5.2")

    def get_symbol_type(
        self, symbol: interfaces.objects.ObjectInterface, symbol_index: int
    ) -> Optional[str]:
        """Determines the type of a given ELF symbol.

        Args:
            symbol: The ELF symbol object (elf_sym)
            symbol_index: The index of the symbol within the type table

        Returns:
            A single-character string representing the symbol type
        """
        try:
            if self.has_member("kallsyms") and self.kallsyms.has_member("typetab"):
                # kernels >= 5.2 1c7651f43777cdd59c1aaa82c87324d3e7438c7b types have its own array
                layer = self._context.layers[self.vol.layer_name]
                sym_type = layer.read(self.section_typetab + symbol_index, 1)
                sym_type = sym_type.decode("utf-8", errors="ignore")
            else:
                # kernels < 5.2 the type was stored in the st_info
                sym_type = chr(symbol.st_info)
        except exceptions.InvalidAddressException:
            vollog.debug(
                f"Page fault encountered when accessing symbol type of index {symbol_index} of ELF at {self.vol.offset:#x} in {self.vol.layer_name}"
            )
            return None

        return sym_type


class task_struct(generic.GenericIntelProcess):
    def is_valid(self) -> bool:
        layer = self._context.layers[self.vol.layer_name]
        # Make sure the entire task content is readable
        if not layer.is_valid(self.vol.offset, self.vol.size):
            return False

        if self.pid < 0 or self.tgid < 0:
            return False

        if self.has_member("signal") and not (
            self.signal and self.signal.is_readable()
        ):
            return False

        if self.has_member("nsproxy") and not (
            self.nsproxy and self.nsproxy.is_readable()
        ):
            return False

        if self.has_member("real_parent") and not (
            self.real_parent and self.real_parent.is_readable()
        ):
            return False

        if (
            self.has_member("active_mm")
            and self.active_mm
            and not self.active_mm.is_readable()
        ):
            return False

        if self.mm:
            if not self.mm.is_readable():
                return False

            if self.mm != self.active_mm:
                return False

        return True

    def add_process_layer(
        self, config_prefix: Optional[str] = None, preferred_name: Optional[str] = None
    ) -> Optional[str]:
        """Constructs a new layer based on the process's DTB.

        Returns the name of the Layer or None.
        """

        parent_layer = self._context.layers[self.vol.layer_name]
        try:
            pgd = self.mm.pgd
        except exceptions.InvalidAddressException:
            return None
        if not isinstance(parent_layer, linear.LinearlyMappedLayer):
            raise TypeError(
                "Parent layer is not a translation layer, unable to construct process layer"
            )
        try:
            dtb, layer_name = parent_layer.translate(pgd)
        except exceptions.InvalidAddressException:
            return None

        if preferred_name is None:
            preferred_name = self.vol.layer_name + f"_Process{self.pid}"
        # Add the constructed layer and return the name
        return self._add_process_layer(
            self._context, dtb, config_prefix, preferred_name
        )

    def get_address_space_layer(
        self,
    ) -> Optional[interfaces.layers.TranslationLayerInterface]:
        """Returns the task layer for this task's address space."""

        task_layer_name = (
            self.vol.layer_name if self.is_kernel_thread else self.add_process_layer()
        )
        if not task_layer_name:
            return None

        return self._context.layers[task_layer_name]

    def get_process_memory_sections(
        self, heap_only: bool = False
    ) -> Generator[Tuple[int, int], None, None]:
        """Returns a list of sections based on the memory manager's view of
        this task's virtual memory."""
        for vma in self.mm.get_vma_iter():
            start = int(vma.vm_start)
            end = int(vma.vm_end)

            if heap_only and not (start <= self.mm.brk and end >= self.mm.start_brk):
                continue
            else:
                # FIXME: Check if this actually needs to be printed out or not
                vollog.info(
                    f"adding vma: {start:x} {self.mm.brk:x} | {end:x} {self.mm.start_brk:x}"
                )
            yield (start, end - start)

    @property
    def is_kernel_thread(self) -> bool:
        """Checks if this task is a kernel thread.

        Returns:
            bool: True, if this task is a kernel thread. Otherwise, False.
        """
        return (self.flags & linux_constants.PF_KTHREAD) != 0

    @property
    def is_thread_group_leader(self) -> bool:
        """Checks if this task is a thread group leader.

        Returns:
            bool: True, if this task is a thread group leader. Otherwise, False.
        """
        return self.tgid == self.pid

    @property
    def is_user_thread(self) -> bool:
        """Checks if this task is a user thread.

        Returns:
            bool: True, if this task is a user thread. Otherwise, False.
        """
        return not self.is_kernel_thread and self.tgid != self.pid

    def _get_tasks_iterable(self) -> Iterable[interfaces.objects.ObjectInterface]:
        """Returns the respective iterable to obtain the threads in this process"""
        vmlinux = linux.LinuxUtilities.get_module_from_volobj_type(self._context, self)
        task_struct_symname = f"{vmlinux.symbol_table_name}{constants.BANG}task_struct"
        if vmlinux.get_type("task_struct").has_member("signal") and vmlinux.get_type(
            "signal_struct"
        ).has_member("thread_head"):
            # kernels >= 6.7 - via signals
            return self.signal.thread_head.to_list(task_struct_symname, "thread_node")
        elif vmlinux.get_type("task_struct").has_member("thread_group"):
            # kernels < 6.7 - via thread_group
            return self.thread_group.to_list(task_struct_symname, "thread_group")

        raise AttributeError("Unable to find the root dentry")

    def get_threads(self) -> Iterable[interfaces.objects.ObjectInterface]:
        """Returns each thread in this process"""
        tasks_iterable = self._get_tasks_iterable()
        threads_seen = set([self.vol.offset])
        for task in tasks_iterable:
            if not task.is_valid():
                continue
            if task.vol.offset not in threads_seen:
                threads_seen.add(task.vol.offset)
                yield task

    @property
    def is_being_ptraced(self) -> bool:
        """Returns True if this task is being traced using ptrace"""
        return self.ptrace != 0

    @property
    def is_ptracing(self) -> bool:
        """Returns True if this task is tracing other tasks using ptrace"""
        is_tracing = (
            self.ptraced.next.is_readable()
            and self.ptraced.next.dereference().vol.offset != self.ptraced.vol.offset
        )
        return is_tracing

    def get_ptrace_tracer_tid(self) -> Optional[int]:
        """Returns the tracer's TID tracing this task"""
        return self.parent.pid if self.is_being_ptraced else None

    def get_ptrace_tracee_tids(self) -> List[int]:
        """Returns the list of TIDs being traced by this task"""
        task_symbol_table_name = self.get_symbol_table_name()

        task_struct_symname = f"{task_symbol_table_name}{constants.BANG}task_struct"
        tracing_tid_list = [
            task_being_traced.pid
            for task_being_traced in self.ptraced.to_list(
                task_struct_symname, "ptrace_entry"
            )
        ]
        return tracing_tid_list

    def get_ptrace_tracee_flags(self) -> Optional[str]:
        """Returns a string with the ptrace flags"""
        return (
            linux_constants.PT_FLAGS(self.ptrace).flags
            if self.is_being_ptraced
            else None
        )

    @property
    def state(self):
        if self.has_member("__state"):
            return self.member("__state")
        elif self.has_member("state"):
            return self.member("state")
        else:
            raise AttributeError("Unsupported task_struct: Cannot find state")

    def _get_task_start_time(self) -> datetime.timedelta:
        """Returns the task's monotonic start_time as a timedelta.

        Returns:
            The task's start time as a timedelta object.
        """
        for member_name in ("start_boottime", "real_start_time", "start_time"):
            if self.has_member(member_name):
                start_time_obj = self.member(member_name)
                start_time_obj_type = start_time_obj.vol.type_name
                start_time_obj_type_name = start_time_obj_type.split(constants.BANG)[1]
                if start_time_obj_type_name != "timespec":
                    # kernels >= 3.17 real_start_time and start_time are u64
                    # kernels >= 5.5 uses start_boottime which is also a u64
                    start_time = Timespec64Concrete.new_from_nsec(start_time_obj)
                else:
                    # kernels < 3.17 real_start_time and start_time are timespec
                    start_time = Timespec64Concrete.new_from_timespec(start_time_obj)

                # This is relative to the boot time so it makes sense to be a timedelta.
                return start_time.to_timedelta()

        raise AttributeError("Unsupported task_struct start_time member")

    def get_time_namespace(self) -> Optional[interfaces.objects.ObjectInterface]:
        """Returns the task's time namespace"""
        vmlinux = linux.LinuxUtilities.get_module_from_volobj_type(self._context, self)
        if not self.has_member("nsproxy"):
            # kernels < 2.6.19: ab516013ad9ca47f1d3a936fa81303bfbf734d52
            return None

        if not vmlinux.get_type("nsproxy").has_member("time_ns"):
            # kernels < 5.6 769071ac9f20b6a447410c7eaa55d1a5233ef40c
            return None

        return self.nsproxy.time_ns

    def get_time_namespace_id(self) -> int:
        """Returns the task's time namespace ID."""
        time_ns = self.get_time_namespace()
        if not time_ns:
            # kernels < 5.6
            return None

        # We are good. ns_common (ns) was introduced in kernels 3.19. So by the time the
        # time namespace was added in kernels 5.6, it already included the ns member.
        return time_ns.ns.inum

    def _get_time_namespace_offsets(
        self,
    ) -> Optional[interfaces.objects.ObjectInterface]:
        """Returns the time offsets from the task's time namespace."""
        time_ns = self.get_time_namespace()
        if not time_ns:
            # kernels < 5.6
            return None

        if not time_ns.has_member("offsets"):
            # kernels < 5.6 af993f58d69ee9c1f421dfc87c3ed231c113989c
            return None

        return time_ns.offsets

    def get_time_namespace_monotonic_offset(
        self,
    ) -> Optional[interfaces.objects.ObjectInterface]:
        """Gets task's time namespace monotonic offset

        Returns:
            a kernel's timespec64 object with the monotonic offset
        """
        time_namespace_offsets = self._get_time_namespace_offsets()
        if not time_namespace_offsets:
            return None

        return time_namespace_offsets.monotonic

    def _get_time_namespace_boottime_offset(
        self,
    ) -> Optional[interfaces.objects.ObjectInterface]:
        """Gets task's time namespace boottime offset

        Returns:
            a kernel's timespec64 object with the boottime offset
        """
        time_namespace_offsets = self._get_time_namespace_offsets()
        if not time_namespace_offsets:
            return None

        return time_namespace_offsets.boottime

    def _get_boottime_raw(self) -> "Timespec64Concrete":
        """Returns the boot time in a Timespec64Concrete object."""

        vmlinux = linux.LinuxUtilities.get_module_from_volobj_type(self._context, self)
        if vmlinux.has_symbol("tk_core"):
            # kernels >= 3.17 | tk_core | 3fdb14fd1df70325e1e91e1203a699a4803ed741
            tk_core = vmlinux.object_from_symbol("tk_core")
            timekeeper = tk_core.timekeeper
            if not timekeeper.offs_real.has_member("tv64"):
                # kernels >= 4.10 - Tested on Ubuntu 6.8.0-41
                boottime_nsec = timekeeper.offs_real - timekeeper.offs_boot
            else:
                # 3.17 <= kernels < 4.10 - Tested on Ubuntu 4.4.0-142
                boottime_nsec = timekeeper.offs_real.tv64 - timekeeper.offs_boot.tv64
            return Timespec64Concrete.new_from_nsec(boottime_nsec)

        elif vmlinux.has_symbol("timekeeper") and vmlinux.get_type(
            "timekeeper"
        ).has_member("wall_to_monotonic"):
            # 3.4 <= kernels < 3.17 - Tested on Ubuntu 3.13.0-185
            timekeeper = vmlinux.object_from_symbol("timekeeper")

            # timekeeper.wall_to_monotonic is timespec
            boottime = Timespec64Concrete.new_from_timespec(
                timekeeper.wall_to_monotonic
            )

            boottime += timekeeper.total_sleep_time

            return boottime.negate()

        elif vmlinux.has_symbol("wall_to_monotonic"):
            # kernels < 3.4 - Tested on Debian7 3.2.0-4 (3.2.57-3+deb7u2)
            wall_to_monotonic = vmlinux.object_from_symbol("wall_to_monotonic")
            boottime = Timespec64Concrete.new_from_timespec(wall_to_monotonic)
            if vmlinux.has_symbol("total_sleep_time"):
                # 2.6.23 <= kernels < 3.4 7c3f1a573237b90ef331267260358a0ec4ac9079
                total_sleep_time = vmlinux.object_from_symbol("total_sleep_time")
                full_type_name = total_sleep_time.vol.type_name
                type_name = full_type_name.split(constants.BANG)[1]
                if type_name == "timespec":
                    # kernels >= 2.6.32 total_sleep_time is a timespec
                    boottime += total_sleep_time
                else:
                    # kernels < 2.6.32 total_sleep_time is an unsigned long as seconds
                    boottime.tv_sec += total_sleep_time

            return boottime.negate()

        raise exceptions.VolatilityException("Unsupported")

    def get_boottime(
        self, root_time_namespace: bool = True
    ) -> Optional[datetime.datetime]:
        """Returns the boot time in UTC as a datetime.

        Args:
            root_time_namespace: If True, it returns the boot time as seen from the root
                time namespace. Otherwise, it returns the boot time relative to the
                task's time namespace.

        Returns:
            A datetime with the UTC boot time.
        """
        boottime = self._get_boottime_raw()
        if not boottime:
            return None

        if not root_time_namespace:
            # Shift boot timestamp according to the task's time namespace offset
            boottime_offset_timespec = self._get_time_namespace_boottime_offset()
            if boottime_offset_timespec:
                # Time namespace support is from kernels 5.6
                boottime -= boottime_offset_timespec

        return boottime.to_datetime()

    def get_create_time(self) -> Optional[datetime.datetime]:
        """Retrieves the task's start time from its time namespace.
        Args:
            context: The context to retrieve required elements (layers, symbol tables) from
            vmlinux_module_name: The name of the kernel module on which to operate
            task: A reference task

        Returns:
            A datetime with task's start time
        """
        # Typically, we want to see the creation time seen from the root time namespace
        boottime = self.get_boottime(root_time_namespace=True)

        # The kernel exports only tv_sec to procfs, see kernel's show_stat().
        # This means user-space tools, like those in the procps package (e.g., ps, top, etc.),
        # only use the boot time seconds to compute dates relatives to this.
        if boottime is None:
            return None
        boottime = boottime.replace(microsecond=0)

        task_start_time_timedelta = self._get_task_start_time()

        # NOTE: Do NOT apply the task's time namespace offsets here. While the kernel uses
        # timens_add_boottime_ns(), it's not needed here since we're seeing it from the
        # root time namespace, not within the task's own time namespace
        return boottime + task_start_time_timedelta

    def get_parent_pid(self) -> int:
        """Returns the parent process ID (PPID)

        This method replicates the Linux kernel's `getppid` syscall behavior.
        Avoid using `task.parent`; instead, use this function for accurate results.
        """

        if self.real_parent and self.real_parent.is_readable():
            ppid = self.real_parent.tgid
        else:
            ppid = 0

        return ppid


class fs_struct(objects.StructType):
    def get_root_dentry(self):
        # < 2.6.26
        if self.has_member("rootmnt"):
            return self.root
        elif self.root.has_member("dentry"):
            return self.root.dentry
        raise AttributeError("Unable to find the root dentry")

    def get_root_mnt(self):
        # < 2.6.26
        if self.has_member("rootmnt"):
            return self.rootmnt
        elif self.root.has_member("mnt"):
            return self.root.mnt
        raise AttributeError("Unable to find the root mount")


class maple_tree(objects.StructType):
    # include/linux/maple_tree.h
    # Mask for Maple Tree Flags
    MT_FLAGS_HEIGHT_MASK = 0x7C
    MT_FLAGS_HEIGHT_OFFSET = 0x02

    # Shift and mask to extract information from maple tree node pointers
    MAPLE_NODE_TYPE_SHIFT = 0x03
    MAPLE_NODE_TYPE_MASK = 0x0F
    MAPLE_NODE_POINTER_MASK = 0xFF

    # types of Maple Tree Nodes
    MAPLE_DENSE = 0
    MAPLE_LEAF_64 = 1
    MAPLE_RANGE_64 = 2
    MAPLE_ARANGE_64 = 3

    def get_slot_iter(self):
        """Parse the Maple Tree and return every non zero slot."""
        maple_tree_offset = self.vol.offset & ~(self.MAPLE_NODE_POINTER_MASK)
        expected_maple_tree_depth = (
            self.ma_flags & self.MT_FLAGS_HEIGHT_MASK
        ) >> self.MT_FLAGS_HEIGHT_OFFSET
        yield from self._parse_maple_tree_node(
            self.ma_root, maple_tree_offset, expected_maple_tree_depth
        )

    def _parse_maple_tree_node(
        self,
        maple_tree_entry,
        parent,
        expected_maple_tree_depth,
        seen=None,
        current_depth=1,
    ) -> Optional[int]:
        """Recursively parse Maple Tree Nodes and yield all non empty slots"""

        # Create seen set if it does not exist, e.g. on the first call into this recursive function. This
        # must be None or an existing set of addresses for MTEs that have already been processed or that
        # should otherwise be ignored. If parsing from the root node for example this should be None on the
        # first call. If you needed to parse all nodes downwards from part of the tree this should still be
        # None. If however you wanted to parse from a node, but ignore some parts of the tree below it then
        # this could be populated with the addresses of the nodes you wish to ignore.

        if seen is None:
            seen = set()

        # protect against unlikely loop
        if maple_tree_entry in seen:
            vollog.warning(
                f"The mte {hex(maple_tree_entry)} has all ready been seen, no further results will be produced for this node."
            )
            return None
        else:
            seen.add(maple_tree_entry)

        # check if we have exceeded the expected depth of this maple tree.
        # e.g. when current_depth is larger than expected_maple_tree_depth there may be an issue.
        # it is normal that expected_maple_tree_depth is equal to current_depth.
        if expected_maple_tree_depth < current_depth:
            vollog.warning(
                f"The depth for the maple tree at {hex(self.vol.offset)} is {expected_maple_tree_depth}, however when parsing the nodes "
                f"a depth of {current_depth} was reached. This is unexpected and may lead to incorrect results."
            )

        # parse the mte to extract the pointer value, node type, and leaf status
        pointer = maple_tree_entry & ~(self.MAPLE_NODE_POINTER_MASK)
        node_type = (
            maple_tree_entry >> self.MAPLE_NODE_TYPE_SHIFT
        ) & self.MAPLE_NODE_TYPE_MASK

        # create a pointer object for the node parent mte (note this will include flags in the low bits)
        symbol_table_name = self.get_symbol_table_name()
        node_parent_mte = self._context.object(
            symbol_table_name + constants.BANG + "pointer",
            layer_name=self.vol.native_layer_name,
            offset=pointer,
        )

        # extract the actual pointer to the parent of this node
        node_parent_pointer = node_parent_mte & ~(self.MAPLE_NODE_POINTER_MASK)

        # verify that the node_parent_pointer correctly points to the parent
        if node_parent_pointer != parent:
            return None

        # create a node object
        node = self._context.object(
            symbol_table_name + constants.BANG + "maple_node",
            layer_name=self.vol.layer_name,
            offset=pointer,
        )

        # parse the slots based on the node type
        if node_type == self.MAPLE_DENSE:
            for slot in node.alloc.slot:
                if (slot & ~(self.MAPLE_NODE_TYPE_MASK)) != 0:
                    yield slot
        elif node_type == self.MAPLE_LEAF_64:
            for slot in node.mr64.slot:
                if (slot & ~(self.MAPLE_NODE_TYPE_MASK)) != 0:
                    yield slot
        elif node_type == self.MAPLE_RANGE_64:
            for slot in node.mr64.slot:
                if (slot & ~(self.MAPLE_NODE_TYPE_MASK)) != 0:
                    yield from self._parse_maple_tree_node(
                        slot,
                        pointer,
                        expected_maple_tree_depth,
                        seen,
                        current_depth + 1,
                    )
        elif node_type == self.MAPLE_ARANGE_64:
            for slot in node.ma64.slot:
                if (slot & ~(self.MAPLE_NODE_TYPE_MASK)) != 0:
                    yield from self._parse_maple_tree_node(
                        slot,
                        pointer,
                        expected_maple_tree_depth,
                        seen,
                        current_depth + 1,
                    )
        else:
            # unkown maple node type
            raise AttributeError(
                f"Unkown Maple Tree node type {node_type} at offset {hex(pointer)}."
            )


class mm_struct(objects.StructType):

    # TODO: As of version 3.0.0 this method should be removed
    def get_mmap_iter(self) -> Iterable[interfaces.objects.ObjectInterface]:
        """
        Deprecated: Use either get_vma_iter() or _get_mmap_iter().
        """
        vollog.warning(
            "This method has been deprecated in favour of using the get_vma_iter() method."
        )
        yield from self.get_vma_iter()

    def _get_mmap_iter(self) -> Iterable[interfaces.objects.ObjectInterface]:
        """Returns an iterator for the mmap list member of an mm_struct. Use this only if
        required, get_vma_iter() will choose the correct _get_maple_tree_iter() or
        _get_mmap_iter() automatically as required.

        Yields:
            vm_area_struct objects
        """

        if not self.has_member("mmap"):
            raise AttributeError(
                "_get_mmap_iter called on mm_struct where no mmap member exists."
            )
        vma_pointer = self.mmap
        if not (vma_pointer and vma_pointer.is_readable()):
            return None
        vma_object = vma_pointer.dereference()
        yield vma_object

        seen = {vma_pointer}
        vma_pointer = vma_pointer.vm_next

        while vma_pointer and vma_pointer.is_readable() and vma_pointer not in seen:
            vma_object = vma_pointer.dereference()
            yield vma_object
            seen.add(vma_pointer)
            vma_pointer = vma_pointer.vm_next

    # TODO: As of version 3.0.0 this method should be removed
    def get_maple_tree_iter(self) -> Iterable[interfaces.objects.ObjectInterface]:
        """
        Deprecated: Use either get_vma_iter() or _get_maple_tree_iter().
        """
        vollog.warning(
            "This method has been deprecated in favour of using the get_vma_iter() method."
        )
        yield from self.get_vma_iter()

    def _get_maple_tree_iter(self) -> Iterable[interfaces.objects.ObjectInterface]:
        """Returns an iterator for the mm_mt member of an mm_struct. Use this only if
        required, get_vma_iter() will choose the correct _get_maple_tree_iter() or
        get_mmap_iter() automatically as required.

        Yields:
            vm_area_struct objects
        """

        if not self.has_member("mm_mt"):
            raise AttributeError(
                "_get_maple_tree_iter called on mm_struct where no mm_mt member exists."
            )
        symbol_table_name = self.get_symbol_table_name()
        for vma_pointer in self.mm_mt.get_slot_iter():
            try:
                vma_object = vma_pointer.dereference().cast(
                    symbol_table_name + constants.BANG + "vm_area_struct"
                )
            except exceptions.InvalidAddressException:
                continue

            # The slots will hold values related to their slot if they are invalid
            # Before this check, this function was returning objects on the first page of memory...
            if vma_object.vol.offset < 0x1000:
                continue

            yield vma_object

    def _do_get_vma_iter(self) -> Iterable[interfaces.objects.ObjectInterface]:
        """Returns an iterator for the VMAs in an mm_struct.
        Automatically choosing the mmap or mm_mt as required.

        Yields:
            vm_area_struct objects
        """

        if self.has_member("mmap"):
            # kernels < 6.1
            yield from self._get_mmap_iter()
        elif self.has_member("mm_mt"):
            # kernels >= 6.1 d4af56c5c7c6781ca6ca8075e2cf5bc119ed33d1
            yield from self._get_maple_tree_iter()
        else:
            raise AttributeError("Unable to find mmap or mm_mt in mm_struct")

    def get_vma_iter(self) -> Iterable[interfaces.objects.ObjectInterface]:
        """Returns an iterator for the VMAs in an mm_struct.
        Automatically choosing the mmap or mm_mt as required.

        Yields:
            vm_area_struct objects
        """
        for vma in self._do_get_vma_iter():
            try:
                vma.vm_start
                vma.vm_end
                vma.get_protection()

                yield vma
            except exceptions.InvalidAddressException:
                vollog.debug(f"Skipping invalid vm_area_struct at {vma.vol.offset:#x}")


class super_block(objects.StructType):
    # include/linux/kdev_t.h
    MINORBITS = 20

    # Superblock flags
    SB_RDONLY = 1  # Mount read-only
    SB_NOSUID = 2  # Ignore suid and sgid bits
    SB_NODEV = 4  # Disallow access to device special files
    SB_NOEXEC = 8  # Disallow program execution
    SB_SYNCHRONOUS = 16  # Writes are synced at once
    SB_MANDLOCK = 64  # Allow mandatory locks on an FS
    SB_DIRSYNC = 128  # Directory modifications are synchronous
    SB_NOATIME = 1024  # Do not update access times
    SB_NODIRATIME = 2048  # Do not update directory access times
    SB_SILENT = 32768
    SB_POSIXACL = 1 << 16  # VFS does not apply the umask
    SB_KERNMOUNT = 1 << 22  # this is a kern_mount call
    SB_I_VERSION = 1 << 23  # Update inode I_version field
    SB_LAZYTIME = 1 << 25  # Update the on-disk [acm]times lazily

    SB_OPTS = {
        SB_SYNCHRONOUS: "sync",
        SB_DIRSYNC: "dirsync",
        SB_MANDLOCK: "mand",
        SB_LAZYTIME: "lazytime",
    }

    @functools.cached_property
    def major(self) -> int:
        return self.s_dev >> self.MINORBITS

    @functools.cached_property
    def minor(self) -> int:
        return self.s_dev & ((1 << self.MINORBITS) - 1)

    @functools.cached_property
    def uuid(self) -> str:
        if not self.has_member("s_uuid"):
            raise AttributeError(
                "super_block struct does not support s_uuid direct attribute access, probably indicating a kernel version < 2.6.39-rc1."
            )

        if self.s_uuid.has_member("b"):
            uuid_as_ints = self.s_uuid.b
        else:
            uuid_as_ints = self.s_uuid

        return str(uuid.UUID(bytes=bytes(uuid_as_ints)))

    def get_flags_access(self) -> str:
        return "ro" if self.s_flags & self.SB_RDONLY else "rw"

    def get_flags_opts(self) -> Iterable[str]:
        sb_opts = [
            self.SB_OPTS[sb_opt] for sb_opt in self.SB_OPTS if sb_opt & self.s_flags
        ]
        return sb_opts

    def get_type(self) -> Optional[str]:
        """Gets the superblock filesystem type string"""

        s_type_ptr = self.s_type
        if not (s_type_ptr and s_type_ptr.is_readable()):
            return None

        s_type_name_ptr = s_type_ptr.name
        if not (s_type_name_ptr and s_type_name_ptr.is_readable()):
            return None

        mnt_sb_type = utility.pointer_to_string(s_type_name_ptr, count=255)
        s_subtype_ptr = self.s_subtype
        if s_subtype_ptr and s_subtype_ptr.is_readable():
            mnt_sb_subtype = utility.pointer_to_string(s_subtype_ptr, count=255)
            mnt_sb_type += "." + mnt_sb_subtype

        return mnt_sb_type


class vm_area_struct(objects.StructType):
    perm_flags = {
        0x00000001: "r",
        0x00000002: "w",
        0x00000004: "x",
    }

    extended_flags = {
        0x00000001: "VM_READ",
        0x00000002: "VM_WRITE",
        0x00000004: "VM_EXEC",
        0x00000008: "VM_SHARED",
        0x00000010: "VM_MAYREAD",
        0x00000020: "VM_MAYWRITE",
        0x00000040: "VM_MAYEXEC",
        0x00000080: "VM_MAYSHARE",
        0x00000100: "VM_GROWSDOWN",
        0x00000200: "VM_NOHUGEPAGE",
        0x00000400: "VM_PFNMAP",
        0x00000800: "VM_DENYWRITE",
        0x00001000: "VM_EXECUTABLE",
        0x00002000: "VM_LOCKED",
        0x00004000: "VM_IO",
        0x00008000: "VM_SEQ_READ",
        0x00010000: "VM_RAND_READ",
        0x00020000: "VM_DONTCOPY",
        0x00040000: "VM_DONTEXPAND",
        0x00080000: "VM_RESERVED",
        0x00100000: "VM_ACCOUNT",
        0x00200000: "VM_NORESERVE",
        0x00400000: "VM_HUGETLB",
        0x00800000: "VM_NONLINEAR",
        0x01000000: "VM_MAPPED_COP__VM_HUGEPAGE",
        0x02000000: "VM_INSERTPAGE",
        0x04000000: "VM_ALWAYSDUMP",
        0x08000000: "VM_CAN_NONLINEAR",
        0x10000000: "VM_MIXEDMAP",
        0x20000000: "VM_SAO",
        0x40000000: "VM_PFN_AT_MMAP",
        0x80000000: "VM_MERGEABLE",
    }

    def _parse_flags(self, vm_flags, parse_flags) -> str:
        """Returns an string representation of the flags in a
        vm_area_struct."""

        retval = ""

        for mask, char in parse_flags.items():
            if (vm_flags & mask) == mask:
                retval = retval + char
            else:
                retval = retval + "-"
        return retval

    # only parse the rwx bits
    def get_protection(self) -> str:
        return self._parse_flags(self.vm_flags & 0b1111, vm_area_struct.perm_flags)

    # used by malfind
    def get_flags(self) -> str:
        return self._parse_flags(self.vm_flags, self.extended_flags)

    def get_page_offset(self) -> int:
        if self.vm_file == 0:
            return 0
        parent_layer = self._context.layers[self.vol.layer_name]
        return self.vm_pgoff << parent_layer.page_shift

    def _do_get_name(self, context, task) -> str:
        if self.vm_file != 0:
            fname = linux.LinuxUtilities.path_for_file(context, task, self.vm_file)
        elif self.vm_start <= task.mm.start_brk and self.vm_end >= task.mm.brk:
            fname = "[heap]"
        elif self.vm_start <= task.mm.start_stack <= self.vm_end:
            fname = "[stack]"
        elif (
            self.vm_mm.context.has_member("vdso")
            and self.vm_start == self.vm_mm.context.vdso
        ):
            fname = "[vdso]"
        else:
            fname = "Anonymous Mapping"
        return fname

    def get_name(self, context, task) -> Optional[str]:
        try:
            return self._do_get_name(context, task)
        except exceptions.InvalidAddressException:
            return None

    # used by malfind
    def is_suspicious(self, proclayer=None):
        ret = False

        flags_str = self.get_protection()

        if flags_str == "rwx":
            ret = True
        elif flags_str == "r-x" and self.vm_file.dereference().vol.offset == 0:
            ret = True
        elif proclayer and "x" in flags_str:
            for i in range(self.vm_start, self.vm_end, proclayer.page_size):
                try:
                    if proclayer.is_dirty(i):
                        vollog.warning(
                            f"Found malicious (dirty+exec) page at {hex(i)} !"
                        )
                        # We do not attempt to find other dirty+exec pages once we have found one
                        ret = True
                        break
                except (
                    exceptions.PagedInvalidAddressException,
                    exceptions.InvalidAddressException,
                ) as excp:
                    vollog.debug(f"Unable to translate address {hex(i)} : {excp}")
                    # Abort as it is likely that other addresses in the same range will also fail
                    ret = False
                    break
        return ret


class qstr(objects.StructType):
    def name_as_str(self) -> str:
        if self.has_member("len"):
            str_length = self.len + 1  # Maximum length should include null terminator
        else:
            str_length = 255
        try:
            ret = utility.pointer_to_string(self.name, str_length)
        except (exceptions.InvalidAddressException, ValueError):
            ret = ""
        return ret


class dentry(objects.StructType):
    def path(self) -> str:
        """Based on __dentry_path Linux kernel function"""
        reversed_path = []
        dentry_seen = set()
        current_dentry = self
        while (
            not current_dentry.is_root()
            and current_dentry.vol.offset not in dentry_seen
        ):
            parent = current_dentry.d_parent
            reversed_path.append(current_dentry.d_name.name_as_str())
            dentry_seen.add(current_dentry.vol.offset)
            current_dentry = parent
        return "/" + "/".join(reversed(reversed_path))

    def is_root(self) -> bool:
        return self.vol.offset == self.d_parent

    def is_subdir(self, old_dentry):
        """Is this dentry a subdirectory of old_dentry?

        Returns true if this dentry is a subdirectory of the parent (at any depth).
        Otherwise, it returns false.
        """
        if self.vol.offset == old_dentry:
            return True
        return self.d_ancestor(old_dentry)

    def d_ancestor(self, ancestor_dentry):
        """Search for an ancestor

        Returns the ancestor dentry which is a child of "ancestor_dentry",
        if "ancestor_dentry" is an ancestor of "child_dentry", else None.
        """

        dentry_seen = set()
        current_dentry = self
        while (
            not current_dentry.is_root()
            and current_dentry.vol.offset not in dentry_seen
        ):
            if current_dentry.d_parent == ancestor_dentry.vol.offset:
                return current_dentry
            dentry_seen.add(current_dentry.vol.offset)
            current_dentry = current_dentry.d_parent
        return None

    def get_subdirs(self) -> Iterable[interfaces.objects.ObjectInterface]:
        """Walks dentry subdirs

        Yields:
            A dentry object
        """
        if self.has_member("d_sib") and self.has_member("d_children"):
            # kernels >= 6.8
            walk_member = "d_sib"
            list_head_member = self.d_children
        elif self.has_member("d_child") and self.has_member("d_subdirs"):
            # 3.19.0 <= kernels < 6.8
            walk_member = "d_child"
            list_head_member = self.d_subdirs
        elif self.has_member("d_u") and self.has_member("d_subdirs"):
            # kernels < 3.19

            # Actually, 'd_u.d_child' but to_list() doesn't support something like that.
            # Since, it's an union, everything is at the same offset than 'd_u'.
            walk_member = "d_u"
            list_head_member = self.d_subdirs
        else:
            raise exceptions.VolatilityException("Unsupported dentry type")

        dentry_type_name = self.get_symbol_table_name() + constants.BANG + "dentry"
        yield from list_head_member.to_list(dentry_type_name, walk_member)

    def get_inode(self) -> Optional[interfaces.objects.ObjectInterface]:
        """Returns the inode associated with this dentry"""

        inode_ptr = self.d_inode
        if not (inode_ptr and inode_ptr.is_readable() and inode_ptr.is_valid()):
            return None

        return inode_ptr.dereference()


class struct_file(objects.StructType):
    def get_dentry(self) -> interfaces.objects.ObjectInterface:
        """Returns a pointer to the dentry associated with this file"""
        if self.has_member("f_path"):
            return self.f_path.dentry

        raise AttributeError("Unable to find file -> dentry")

    def get_vfsmnt(self) -> interfaces.objects.ObjectInterface:
        """Returns the fs (vfsmount) where this file is mounted"""
        if self.has_member("f_path"):
            return self.f_path.mnt

        raise AttributeError("Unable to find file -> vfs mount")

    def get_inode(self) -> Optional[interfaces.objects.ObjectInterface]:
        """Returns an inode associated with this file"""

        inode_ptr = None
        if self.has_member("f_inode") and self.f_inode and self.f_inode.is_readable():
            # Try first the cached value, kernels +3.9
            inode_ptr = self.f_inode

        if not (inode_ptr and inode_ptr.is_readable() and inode_ptr.is_valid()):
            dentry_ptr = self.get_dentry()
            if not (dentry_ptr and dentry_ptr.is_readable()):
                return None

            inode_ptr = dentry_ptr.d_inode

        if not (inode_ptr and inode_ptr.is_readable() and inode_ptr.is_valid()):
            return None

        return inode_ptr.dereference()


class list_head(objects.StructType, collections.abc.Iterable):
    def to_list(
        self,
        symbol_type: str,
        member: str,
        forward: bool = True,
        sentinel: bool = True,
        layer: Optional[str] = None,
    ) -> Iterator[interfaces.objects.ObjectInterface]:
        """Returns an iterator of the entries in the list.

        Args:
                symbol_type: Type of the list elements
                member: Name of the list_head member in the list elements
                forward: Set false to go backwards
                sentinel: Whether self is a "sentinel node", meaning it is not embedded in a member of the list
                Sentinel nodes are NOT yielded. See https://en.wikipedia.org/wiki/Sentinel_node for further reference
                layer: Name of layer to read from
        Yields:
            Objects of the type specified via the "symbol_type" argument.

        """
        layer_name = layer or self.vol.layer_name

        trans_layer = self._context.layers[layer_name]
        if not trans_layer.is_valid(self.vol.offset):
            return None

        relative_offset = self._context.symbol_space.get_type(
            symbol_type
        ).relative_child_offset(member)

        direction = "next" if forward else "prev"

        link_ptr = getattr(self, direction)
        if not (link_ptr and link_ptr.is_readable()):
            return None
        link = link_ptr.dereference()

        if not sentinel:
            obj_offset = self.vol.offset - relative_offset
            if not trans_layer.is_valid(obj_offset):
                return None

            yield self._context.object(symbol_type, layer_name, offset=obj_offset)

        seen = {self.vol.offset}
        while link.vol.offset not in seen:
            obj_offset = link.vol.offset - relative_offset
            if not trans_layer.is_valid(obj_offset):
                return None

            yield self._context.object(symbol_type, layer_name, offset=obj_offset)

            seen.add(link.vol.offset)
            link_ptr = getattr(link, direction)
            if not (link_ptr and link_ptr.is_readable()):
                break
            link = link_ptr.dereference()

    def __iter__(self) -> Iterator[interfaces.objects.ObjectInterface]:
        return self.to_list(self.vol.parent.vol.type_name, self.vol.member_name)


class hlist_head(objects.StructType):
    def to_list(
        self,
        symbol_type: str,
        member: str,
    ) -> Iterator[interfaces.objects.ObjectInterface]:
        """Returns an iterator of the entries in the list.

        This is a doubly linked list; however, it is not circular, so the 'forward' field
        doesn't make sense. Also, the sentinel concept doesn't make sense here either;
        unlike list_head, the head and nodes each have their own distinct types. A list_head
        cannot be a node by itself.
        - The 'pprev' of the first 'hlist_node' points to the 'hlist_head', not to the last node.
        - The last element 'next' member is NULL

        Args:
            symbol_type: Type of the list elements
            member: Name of the list_head member in the list elements

        Yields:
            Objects of the type specified via the "symbol_type" argument.

        """
        vmlinux = linux.LinuxUtilities.get_module_from_volobj_type(self._context, self)

        current = self.first
        while current and current.is_readable():
            yield linux.LinuxUtilities.container_of(
                current, symbol_type, member, vmlinux
            )

            current = current.next


class files_struct(objects.StructType):
    def get_fds(self) -> interfaces.objects.ObjectInterface:
        if self.has_member("fdt"):
            return self.fdt.fd.dereference()
        elif self.has_member("fd"):
            return self.fd.dereference()
        else:
            raise AttributeError("Unable to find files -> file descriptors")

    def get_max_fds(self) -> interfaces.objects.ObjectInterface:
        if self.has_member("fdt"):
            return self.fdt.max_fds
        elif self.has_member("max_fds"):
            return self.max_fds
        else:
            raise AttributeError("Unable to find files -> maximum file descriptors")


class mount(objects.StructType):
    MNT_NOSUID = 0x01
    MNT_NODEV = 0x02
    MNT_NOEXEC = 0x04
    MNT_NOATIME = 0x08
    MNT_NODIRATIME = 0x10
    MNT_RELATIME = 0x20
    MNT_READONLY = 0x40
    MNT_SHRINKABLE = 0x100
    MNT_WRITE_HOLD = 0x200
    MNT_SHARED = 0x1000
    MNT_UNBINDABLE = 0x2000

    MNT_FLAGS = {
        MNT_NOSUID: "nosuid",
        MNT_NODEV: "nodev",
        MNT_NOEXEC: "noexec",
        MNT_NOATIME: "noatime",
        MNT_NODIRATIME: "nodiratime",
        MNT_RELATIME: "relatime",
    }

    def get_mnt_sb(self) -> int:
        """Returns a pointer to the super_block"""
        if self.has_member("mnt"):
            return self.mnt.mnt_sb
        elif self.has_member("mnt_sb"):
            return self.mnt_sb
        else:
            raise AttributeError("Unable to find mount -> super block")

    def get_mnt_root(self):
        if self.has_member("mnt"):
            return self.mnt.mnt_root
        elif self.has_member("mnt_root"):
            return self.mnt_root
        else:
            raise AttributeError("Unable to find mount -> mount root")

    def get_mnt_flags(self):
        if self.has_member("mnt"):
            return self.mnt.mnt_flags
        elif self.has_member("mnt_flags"):
            return self.mnt_flags
        else:
            raise AttributeError("Unable to find mount -> mount flags")

    def get_mnt_parent(self):
        """Gets the fs where we are mounted on

        Returns:
            A mount pointer
        """
        return self.mnt_parent

    def get_mnt_mountpoint(self):
        """Gets the dentry of the mountpoint

        Returns:
            A dentry pointer
        """

        return self.mnt_mountpoint

    def get_parent_mount(self):
        return self.mnt.get_parent_mount()

    def has_parent(self) -> bool:
        """Checks if this mount has a parent

        Returns:
            bool: 'True' if this mount has a parent
        """
        return self.mnt_parent != self.vol.offset

    def get_vfsmnt_current(self):
        """Returns the fs where we are mounted on

        Returns:
            A 'vfsmount'
        """
        return self.mnt

    def get_vfsmnt_parent(self):
        """Gets the parent fs (vfsmount) to where it's mounted on

        Returns:
            A 'vfsmount'
        """

        return self.get_mnt_parent().get_vfsmnt_current()

    def get_dentry_current(self):
        """Returns the root of the mounted tree

        Returns:
            A dentry pointer
        """
        vfsmnt = self.get_vfsmnt_current()
        dentry_pointer = vfsmnt.mnt_root

        return dentry_pointer

    def get_dentry_parent(self):
        """Returns the parent root of the mounted tree

        Returns:
            A dentry pointer
        """

        return self.get_mnt_parent().get_dentry_current()

    def get_flags_access(self) -> str:
        return "ro" if self.get_mnt_flags() & self.MNT_READONLY else "rw"

    def get_flags_opts(self) -> Iterable[str]:
        flags = [
            self.MNT_FLAGS[mntflag]
            for mntflag in self.MNT_FLAGS
            if mntflag & self.get_mnt_flags()
        ]
        return flags

    def is_shared(self) -> bool:
        return self.get_mnt_flags() & self.MNT_SHARED

    def is_unbindable(self) -> bool:
        return self.get_mnt_flags() & self.MNT_UNBINDABLE

    def is_slave(self) -> bool:
        return self.mnt_master and self.mnt_master.vol.offset != 0

    def get_devname(self) -> str:
        return utility.pointer_to_string(self.mnt_devname, count=255)

    def get_dominating_id(self, root) -> int:
        """Get ID of closest dominating peer group having a representative under the given root."""
        mnt_seen = set()
        current_mnt = self.mnt_master
        while (
            current_mnt
            and current_mnt.vol.offset != 0
            and current_mnt.vol.offset not in mnt_seen
        ):
            peer = current_mnt.get_peer_under_root(self.mnt_ns, root)
            if peer and peer.vol.offset != 0:
                return peer.mnt_group_id
            mnt_seen.add(current_mnt.vol.offset)
            current_mnt = current_mnt.mnt_master
        return 0

    def get_peer_under_root(self, ns, root):
        """Return true if path is reachable from root.
        It mimics the kernel function is_path_reachable(), ref: fs/namespace.c
        """
        mnt_seen = set()
        current_mnt = self
        while current_mnt.vol.offset not in mnt_seen:
            if current_mnt.mnt_ns == ns and current_mnt.is_path_reachable(
                current_mnt.mnt.mnt_root, root
            ):
                return current_mnt
            mnt_seen.add(current_mnt.vol.offset)
            current_mnt = current_mnt.next_peer()
            if current_mnt.vol.offset == self.vol.offset:
                break
        return None

    def is_path_reachable(self, current_dentry, root):
        """Return true if path is reachable.
        It mimics the kernel function with same name, ref fs/namespace.c:
        """
        mnt_seen = set()
        current_mnt = self
        while (
            current_mnt.mnt.vol.offset != root.mnt
            and current_mnt.has_parent()
            and current_mnt.vol.offset not in mnt_seen
        ):
            current_dentry = current_mnt.mnt_mountpoint
            mnt_seen.add(current_mnt.vol.offset)
            current_mnt = current_mnt.mnt_parent
        return current_mnt.mnt.vol.offset == root.mnt and current_dentry.is_subdir(
            root.dentry
        )

    def next_peer(self):
        table_name = self.vol.type_name.split(constants.BANG)[0]
        mount_struct = f"{table_name}{constants.BANG}mount"
        offset = self._context.symbol_space.get_type(
            mount_struct
        ).relative_child_offset("mnt_share")

        return self._context.object(
            mount_struct,
            self.vol.layer_name,
            offset=self.mnt_share.next.vol.offset - offset,
        )


class vfsmount(objects.StructType):
    def is_valid(self):
        return (
            self.get_mnt_sb() != 0
            and self.get_mnt_root() != 0
            and self.get_mnt_parent() != 0
        )

    def _is_kernel_prior_to_struct_mount(self) -> bool:
        """Helper to distinguish between kernels prior to version 3.3 which lacked the
        'mount' struct, versus later versions that include it.
        See 7d6fec45a5131918b51dcd76da52f2ec86a85be6.

        # Following that commit, also in kernel version 3.3 (3376f34fff5be9954fd9a9c4fd68f4a0a36d480e),
        # the 'mnt_parent' member was relocated from the 'vfsmount' struct to the newly
        # introduced 'mount' struct.

        Returns:
            'True' if the kernel lacks the 'mount' struct, typically indicating kernel < 3.3.
        """

        return self.has_member("mnt_parent")

    def is_equal(self, vfsmount_ptr) -> bool:
        """Helper to make sure it is comparing two pointers to 'vfsmount'.

        Depending on the kernel version, see 3376f34fff5be9954fd9a9c4fd68f4a0a36d480e,
        the calling object (self) could be a 'vfsmount \\*' (<3.3) or a 'vfsmount' (>=3.3).
        This way we trust in the framework "auto" dereferencing ability to assure that
        when we reach this point 'self' will be a 'vfsmount' already and self.vol.offset
        a 'vfsmount \\*' and not a 'vfsmount \\*\\*'. The argument must be a 'vfsmount \\*'.
        Typically, it's called from do_get_path().

        Args:
            vfsmount_ptr: A pointer to a 'vfsmount'

        Raises:
            exceptions.VolatilityException: If vfsmount_ptr is not a 'vfsmount \\*'

        Returns:
            'True' if the given argument points to the same 'vfsmount' as 'self'.
        """
        if isinstance(vfsmount_ptr, objects.Pointer):
            return self.vol.offset == vfsmount_ptr
        else:
            raise exceptions.VolatilityException(
                "Unexpected argument type. It has to be a 'vfsmount *'"
            )

    def _get_real_mnt(self) -> interfaces.objects.ObjectInterface:
        """Gets the struct 'mount' containing this 'vfsmount'.

        It should be only called from kernels >= 3.3 when 'struct mount' was introduced.
        See 7d6fec45a5131918b51dcd76da52f2ec86a85be6

        Returns:
            The 'mount' object containing this 'vfsmount'.
        """
        vmlinux = linux.LinuxUtilities.get_module_from_volobj_type(self._context, self)
        return linux.LinuxUtilities.container_of(
            self.vol.offset, "mount", "mnt", vmlinux
        )

    def get_vfsmnt_current(self):
        """Returns the current fs where we are mounted on

        Returns:
            A vfsmount pointer
        """
        return self.get_mnt_parent()

    def get_vfsmnt_parent(self):
        """Gets the parent fs (vfsmount) to where it's mounted on

        Returns:
            For kernels <  3.3: A vfsmount pointer
            For kernels >= 3.3: A vfsmount object
        """
        if self._is_kernel_prior_to_struct_mount():
            return self.get_mnt_parent()
        else:
            return self._get_real_mnt().get_vfsmnt_parent()

    def get_dentry_current(self):
        """Returns the root of the mounted tree

        Returns:
            A dentry pointer
        """
        if self._is_kernel_prior_to_struct_mount():
            return self.get_mnt_mountpoint()
        else:
            return self._get_real_mnt().get_dentry_current()

    def get_dentry_parent(self):
        """Returns the parent root of the mounted tree

        Returns:
            A dentry pointer
        """
        if self._is_kernel_prior_to_struct_mount():
            return self.get_mnt_mountpoint()
        else:
            return self._get_real_mnt().get_mnt_mountpoint()

    def get_mnt_parent(self):
        """Gets the mnt_parent member.

        Returns:
            For kernels <  3.3: A vfsmount pointer
            For kernels >= 3.3: A mount pointer
        """
        if self._is_kernel_prior_to_struct_mount():
            return self.mnt_parent
        else:
            return self._get_real_mnt().get_mnt_parent()

    def get_mnt_mountpoint(self):
        """Gets the dentry of the mountpoint

        Returns:
            A dentry pointer
        """
        if self.has_member("mnt_mountpoint"):
            return self.mnt_mountpoint
        else:
            return self._get_real_mnt().mnt_mountpoint

    def get_mnt_root(self):
        return self.mnt_root

    def has_parent(self) -> bool:
        if self._is_kernel_prior_to_struct_mount():
            return self.mnt_parent != self.vol.offset
        else:
            return self._get_real_mnt().has_parent()

    def get_mnt_sb(self):
        """Returns a pointer to the super_block"""
        return self.mnt_sb

    def get_flags_access(self) -> str:
        return "ro" if self.mnt_flags & mount.MNT_READONLY else "rw"

    def get_flags_opts(self) -> Iterable[str]:
        flags = [
            mntflagtxt
            for mntflag, mntflagtxt in mount.MNT_FLAGS.items()
            if mntflag & self.mnt_flags != 0
        ]
        return flags

    def get_mnt_flags(self):
        return self.mnt_flags

    def is_shared(self) -> bool:
        return self.get_mnt_flags() & mount.MNT_SHARED

    def is_unbindable(self) -> bool:
        return self.get_mnt_flags() & mount.MNT_UNBINDABLE

    def is_slave(self) -> bool:
        return self.mnt_master and self.mnt_master.vol.offset != 0

    def get_devname(self) -> str:
        return utility.pointer_to_string(self.mnt_devname, count=255)


class kobject(objects.StructType):
    def reference_count(self):
        refcnt = self.kref.refcount
        if refcnt.has_member("counter"):
            ret = refcnt.counter
        else:
            ret = refcnt.refs.counter
        return ret


class mnt_namespace(objects.StructType):
    def get_inode(self):
        if self.has_member("proc_inum"):
            # 98f842e675f96ffac96e6c50315790912b2812be 3.8 <= kernels < 3.19
            return self.proc_inum
        elif self.has_member("ns") and self.ns.has_member("inum"):
            # kernels >= 3.19 435d5f4bb2ccba3b791d9ef61d2590e30b8e806e
            return self.ns.inum
        else:
            raise AttributeError("Unable to find mnt_namespace inode")

    def get_mount_points(
        self,
    ) -> Iterator[Optional[interfaces.objects.ObjectInterface]]:
        """Yields the mount points for this mount namespace.

        Yields:
            mount struct instances
        """
        table_name = self.vol.type_name.split(constants.BANG)[0]

        if self.has_member("list"):
            # kernels < 6.8
            mnt_type = table_name + constants.BANG + "mount"
            if not self._context.symbol_space.has_type(mnt_type):
                # In kernels < 3.3, the 'mount' struct didn't exist, and the 'mnt_list'
                # member was part of the 'vfsmount' struct.
                mnt_type = table_name + constants.BANG + "vfsmount"

            yield from self.list.to_list(mnt_type, "mnt_list")
        elif (
            self.has_member("mounts")
            and self.mounts.vol.type_name == table_name + constants.BANG + "rb_root"
        ):
            # kernels >= 6.8
            vmlinux = linux.LinuxUtilities.get_module_from_volobj_type(
                self._context, self
            )
            for node in self.mounts.get_nodes():
                mnt = linux.LinuxUtilities.container_of(
                    node, "mount", "mnt_list", vmlinux
                )
                yield mnt
        else:
            raise exceptions.VolatilityException(
                "Unsupported kernel mount namespace implementation"
            )


class bpf_prog(objects.StructType):
    _BPF_PROG_CHUNK_SHIFT = 6
    _BPF_PROG_CHUNK_SIZE = 1 << _BPF_PROG_CHUNK_SHIFT
    _BPF_PROG_CHUNK_MASK = ~(_BPF_PROG_CHUNK_SIZE - 1)

    def get_type(self) -> Union[str, None]:
        """Returns a string with the eBPF program type"""

        # The program type was in `bpf_prog_aux::prog_type` from 3.18.140 to
        # 4.1.52 before it was moved to `bpf_prog::type`
        if self.has_member("type"):
            # kernel >= 4.1.52
            return self.type.description

        if self.has_member("aux") and self.aux:
            if self.aux.has_member("prog_type"):
                # 3.18.140 <= kernel < 4.1.52
                return self.aux.prog_type.description

        # kernel < 3.18.140
        return None

    def get_tag(self) -> Union[str, None]:
        """Returns a string with the eBPF program tag"""
        # 'tag' was added in kernels 4.10
        if not self.has_member("tag"):
            return None

        vmlinux = linux.LinuxUtilities.get_module_from_volobj_type(self._context, self)
        vmlinux_layer = vmlinux.context.layers[vmlinux.layer_name]

        prog_tag_addr = self.tag.vol.offset
        prog_tag_size = self.tag.count
        if not vmlinux_layer.is_valid(prog_tag_addr, prog_tag_size):
            vollog.debug("Unable to read bpf tag string from 0x%x", prog_tag_addr)
            return None

        prog_tag_bytes = vmlinux_layer.read(prog_tag_addr, prog_tag_size)
        prog_tag = binascii.hexlify(prog_tag_bytes).decode()
        return prog_tag

    def get_name(self) -> Union[str, None]:
        """Returns a string with the eBPF program name"""
        if not self.has_member("aux"):
            # 'prog_aux' was added in kernels 3.18
            return None

        try:
            return self.aux.get_name()
        except exceptions.InvalidAddressException:
            return None

    def bpf_jit_binary_hdr_address(self) -> int:
        """Return the jitted BPF program start address
        Based on bpf_jit_binary_hdr()

        Returns:
            The BPF program address
        """
        vmlinux = linux.LinuxUtilities.get_module_from_volobj_type(self._context, self)
        vmlinux_layer = vmlinux.context.layers[vmlinux.layer_name]

        # In 5.18 (33c9805860e584b194199cab1a1e81f4e6395408) <= kernels < 6.0 (1d5f82d9dd477d5c66e0214a68c3e4f308eadd6d)
        # 'bpf_prog_aux' has a 'use_bpf_prog_pack' member
        bpf_prog_aux_has_use_bpf_prog_pack = vmlinux.get_type(
            "bpf_prog_aux"
        ).has_member("use_bpf_prog_pack")
        if bpf_prog_aux_has_use_bpf_prog_pack and self.aux.use_bpf_prog_pack:
            long_mask = (1 << vmlinux_layer.bits_per_register) - 1
            addr_mask = self._BPF_PROG_CHUNK_MASK & long_mask
        else:
            addr_mask = vmlinux_layer.page_mask

        real_start = self.bpf_func
        return real_start & addr_mask

    def get_address_region(self) -> Tuple[int, int]:
        """Returns the start and end memory addresses of the BPF program.
        Based on bpf_get_prog_addr_region()

        Returns:
            A tuple with the addresses representing the memory range (start, end) of the BPF program.
        """
        vmlinux = linux.LinuxUtilities.get_module_from_volobj_type(self._context, self)
        vmlinux_layer = vmlinux.context.layers[vmlinux.layer_name]
        # Based on bpf_get_prog_addr_region()
        bpf_start_address = self.bpf_jit_binary_hdr_address()

        if vmlinux.has_type("bpf_binary_header"):
            # kernels >= 3.11 314beb9bcabfd6b4542ccbced2402af2c6f6142a
            bpf_binary_header = vmlinux.object(
                object_type="bpf_binary_header", offset=bpf_start_address, absolute=True
            )
            pages = bpf_binary_header.pages
        else:
            # kernels < 3.11 The first member is always the size
            pages = vmlinux.object(
                object_type="unsigned int", offset=bpf_start_address, absolute=True
            )

        bpf_end_address = bpf_start_address + pages * vmlinux_layer.page_size

        return bpf_start_address, bpf_end_address


class bpf_prog_aux(objects.StructType):
    def get_name(self) -> Union[str, None]:
        """Returns a string with the eBPF program name"""
        if not self.has_member("name"):
            # 'name' was added in kernels 4.15
            return None

        try:
            if not self.name:
                return None
            return utility.array_to_string(self.name)
        except exceptions.InvalidAddressException:
            return None


class cred(objects.StructType):
    # struct cred was added in kernels 2.6.29
    def _get_cred_int_value(self, member: str) -> int:
        """Helper to obtain the right cred member value for the current kernel.

        Args:
            member (str): The requested cred member name to obtain its value

        Raises:
            AttributeError: When the requested cred member doesn't exist
            AttributeError: When the cred implementation is not supported.

        Returns:
            int: The cred member value
        """
        if not self.has_member(member):
            raise AttributeError(f"struct cred doesn't have a '{member}' member")

        cred_val = self.member(member)
        if hasattr(cred_val, "val"):
            # From kernels 3.5.7 on it is a 'kuid_t' type
            value = cred_val.val
        elif isinstance(cred_val, objects.Integer):
            # From at least 2.6.30 and until 3.5.7 it was a 'uid_t' type which was an 'unsigned int'
            value = cred_val
        else:
            raise AttributeError("Kernel struct cred is not supported")

        return int(value)

    @property
    def uid(self) -> int:
        """Returns the real user ID

        Returns:
            The real user ID value
        """
        return self._get_cred_int_value("uid")

    @property
    def gid(self) -> int:
        """Returns the real user ID

        Returns:
            The real user ID value
        """
        return self._get_cred_int_value("gid")

    @property
    def euid(self) -> int:
        """Returns the effective user ID

        Returns:
            The effective user ID value
        """
        return self._get_cred_int_value("euid")

    @property
    def egid(self) -> int:
        """Returns the effective group ID

        Returns:
            int: the effective user ID value
        """
        return self._get_cred_int_value("egid")


class kernel_cap_struct(objects.StructType):
    # struct kernel_cap_struct exists from 2.1.92 <= kernels < 6.3
    @classmethod
    def get_last_cap_value(cls) -> int:
        """Returns the latest capability ID supported by the framework.

        Returns:
            int: The latest capability ID supported by the framework.
        """
        return len(linux_constants.CAPABILITIES) - 1

    def get_kernel_cap_full(self) -> int:
        """Return the maximum value allowed for this kernel for a capability

        Returns:
            int: The capability full bitfield mask
        """
        vmlinux = linux.LinuxUtilities.get_module_from_volobj_type(self._context, self)
        try:
            cap_last_cap = vmlinux.object_from_symbol(symbol_name="cap_last_cap")
        except exceptions.SymbolError:
            # It should be a kernel < 3.2, let's use our list of capabilities
            cap_last_cap = self.get_last_cap_value()

        return (1 << cap_last_cap + 1) - 1

    @classmethod
    def capabilities_to_string(cls, capabilities_bitfield: int) -> List[str]:
        """Translates a capability bitfield to a list of capability strings.

        Args:
            capabilities_bitfield (int): The capability bitfield value.

        Returns:
            List[str]: A list of capability strings.
        """

        capabilities = []
        for bit, name in enumerate(linux_constants.CAPABILITIES):
            if capabilities_bitfield & (1 << bit) != 0:
                capabilities.append(name)

        return capabilities

    def get_capabilities(self) -> int:
        """Returns the capability bitfield value

        Returns:
            int: The capability bitfield value.
        """

        if not self.has_member("cap"):
            raise exceptions.VolatilityException(
                "Unsupported kernel capabilities implementation"
            )

        if isinstance(self.cap, objects.Array):
            if len(self.cap) == 1:
                # At least in the vanilla kernel, from 2.6.24 to 2.6.25
                # kernel_cap_struct::cap become a two elements array.
                # However, in some distros or custom kernel can technically
                # be _KERNEL_CAPABILITY_U32S = _LINUX_CAPABILITY_U32S_1
                # Leaving this code here for the sake of ensuring completeness.
                cap_value = self.cap[0]
            elif len(self.cap) == 2:
                # In 2.6.25.x <= kernels < 6.3 kernel_cap_struct::cap is a two
                # elements __u32 array that constitutes a 64bit bitfield.
                cap_value = (self.cap[1] << 32) | self.cap[0]
            else:
                raise exceptions.VolatilityException(
                    "Unsupported kernel capabilities implementation"
                )
        else:
            # In kernels < 2.6.25.x kernel_cap_struct::cap is a __u32
            cap_value = self.cap

        return cap_value & self.get_kernel_cap_full()

    def enumerate_capabilities(self) -> List[str]:
        """Returns the list of capability strings.

        Returns:
            List[str]: The list of capability strings.
        """
        capabilities_value = self.get_capabilities()
        return self.capabilities_to_string(capabilities_value)

    def has_capability(self, capability: str) -> bool:
        """Checks if the given capability string is enabled.

        Args:
            capability (str): A string representing the capability i.e. dac_read_search

        Raises:
            AttributeError: If the given capability is unknown to the framework.

        Returns:
            bool: "True" if the given capability is enabled.
        """
        if capability not in linux_constants.CAPABILITIES:
            raise AttributeError(f"Unknown capability with name '{capability}'")

        cap_value = 1 << linux_constants.CAPABILITIES.index(capability)
        return cap_value & self.get_capabilities() != 0


class kernel_cap_t(kernel_cap_struct):
    # In kernels 6.3 kernel_cap_struct became the kernel_cap_t typedef
    def get_capabilities(self) -> int:
        """Returns the capability bitfield value

        Returns:
            int: The capability bitfield value.
        """

        if self.has_member("val"):
            # In kernels >= 6.3 kernel_cap_t::val is a u64
            cap_value = self.val
        else:
            raise exceptions.VolatilityException(
                "Unsupported kernel capabilities implementation"
            )

        return cap_value & self.get_kernel_cap_full()


class Timespec64Abstract(abc.ABC):
    """Abstract class to handle all required timespec64 operations, convertions and
    adjustments."""

    @classmethod
    def new_from_timespec(cls, other) -> "Timespec64Concrete":
        """Creates a new instance from an Timespec64Abstract subclass object"""
        if not isinstance(other, Timespec64Abstract):
            raise TypeError("Requires an object subclass of Timespec64Abstract")

        tv_sec = int(other.tv_sec)
        tv_nsec = int(other.tv_nsec)
        return Timespec64Concrete(tv_sec=tv_sec, tv_nsec=tv_nsec)

    @classmethod
    def new_from_nsec(cls, nsec) -> "Timespec64Concrete":
        """Creates a new instance from an integer in nanoseconds"""

        # Based on ns_to_timespec64()
        if nsec > 0:
            tv_sec = nsec // linux_constants.NSEC_PER_SEC
            tv_nsec = nsec % linux_constants.NSEC_PER_SEC
        elif nsec < 0:
            tv_sec = -((-nsec - 1) // linux_constants.NSEC_PER_SEC) - 1
            rem = (-nsec - 1) % linux_constants.NSEC_PER_SEC
            tv_nsec = linux_constants.NSEC_PER_SEC - rem - 1
        else:
            tv_sec = tv_nsec = 0

        return Timespec64Concrete(tv_sec=tv_sec, tv_nsec=tv_nsec)

    def to_datetime(self) -> datetime.datetime:
        """Converts this Timespec64Abstract subclass object to a UTC aware datetime"""

        # pylint: disable=E1101
        return conversion.unixtime_to_datetime(
            self.tv_sec + self.tv_nsec / linux_constants.NSEC_PER_SEC
        )

    def to_timedelta(self) -> datetime.timedelta:
        """Converts this Timespec64Abstract subclass object to timedelta"""
        # pylint: disable=E1101
        return datetime.timedelta(
            seconds=self.tv_sec + self.tv_nsec / linux_constants.NSEC_PER_SEC
        )

    def __add__(self, other) -> "Timespec64Concrete":
        """Returns a new Timespec64Concrete object that sums the current values with those
        in the timespec argument"""
        if not isinstance(other, Timespec64Abstract):
            raise TypeError("Requires an object subclass of Timespec64Abstract")

        # pylint: disable=E1101
        result = Timespec64Concrete(
            tv_sec=self.tv_sec + other.tv_sec,
            tv_nsec=self.tv_nsec + other.tv_nsec,
        )

        result.normalize()

        return result

    def __sub__(self, other) -> "Timespec64Concrete":
        """Returns a new Timespec64Abstract object that subtracts the values in the timespec
        argument from the current object's values"""
        if not isinstance(other, Timespec64Abstract):
            raise TypeError("Requires an object subclass of Timespec64Abstract")

        return self + other.negate()

    def negate(self) -> "Timespec64Concrete":
        """Returns a new Timespec64Concrete object with the values of the current object negated"""
        # pylint: disable=E1101
        result = Timespec64Concrete(
            tv_sec=-self.tv_sec,
            tv_nsec=-self.tv_nsec,
        )

        result.normalize()

        return result

    def normalize(self):
        """Normalize any overflow in tv_sec and tv_nsec."""
        # Based on kernel's set_normalized_timespec64()

        # pylint: disable=E1101
        while self.tv_nsec >= linux_constants.NSEC_PER_SEC:
            self.tv_nsec -= linux_constants.NSEC_PER_SEC
            self.tv_sec += 1

        while self.tv_nsec < 0:
            self.tv_nsec += linux_constants.NSEC_PER_SEC
            self.tv_sec -= 1


class Timespec64Concrete(Timespec64Abstract):
    """Handle all required timespec64 operations, convertions and adjustments.
    This is used to dynamically create timespec64-like objects, each with its own variables
    and the same methods as a timespec64 object extension.
    """

    def __init__(self, tv_sec=0, tv_nsec=0):
        self.tv_sec = tv_sec
        self.tv_nsec = tv_nsec


class timespec64(Timespec64Abstract, objects.StructType):
    """Handle all required timespec64 operations, convertions and adjustments.
    This works as an extension of the timespec64 object while maintaining the same methods
    as a Timespec64Concrete object.
    """


class inode(objects.StructType):
    def is_valid(self) -> bool:
        # i_count is a 'signed' counter (atomic_t). Smear, or essentially a wrong inode
        # pointer, will easily cause an integer overflow here.
        return self.i_ino > 0 and self.i_count.counter >= 0

    @property
    def is_dir(self) -> bool:
        """Returns True if the inode is a directory"""
        return stat.S_ISDIR(self.i_mode) != 0

    @property
    def is_reg(self) -> bool:
        """Returns True if the inode is a regular file"""
        return stat.S_ISREG(self.i_mode) != 0

    @property
    def is_link(self) -> bool:
        """Returns True if the inode is a symlink"""
        return stat.S_ISLNK(self.i_mode) != 0

    @property
    def is_fifo(self) -> bool:
        """Returns True if the inode is a FIFO"""
        return stat.S_ISFIFO(self.i_mode) != 0

    @property
    def is_sock(self) -> bool:
        """Returns True if the inode is a socket"""
        return stat.S_ISSOCK(self.i_mode) != 0

    @property
    def is_block(self) -> bool:
        """Returns True if the inode is a block device"""
        return stat.S_ISBLK(self.i_mode) != 0

    @property
    def is_char(self) -> bool:
        """Returns True if the inode is a char device"""
        return stat.S_ISCHR(self.i_mode) != 0

    @property
    def is_sticky(self) -> bool:
        """Returns True if the sticky bit is set"""
        return (self.i_mode & stat.S_ISVTX) != 0

    def get_inode_type(self) -> Union[str, None]:
        """Returns inode type name

        Returns:
            The inode type name
        """
        if self.is_dir:
            return "DIR"
        elif self.is_reg:
            return "REG"
        elif self.is_link:
            return "LNK"
        elif self.is_fifo:
            return "FIFO"
        elif self.is_sock:
            return "SOCK"
        elif self.is_char:
            return "CHR"
        elif self.is_block:
            return "BLK"
        else:
            return None

    def _time_member_to_datetime(
        self, member
    ) -> Union[datetime.datetime, interfaces.renderers.BaseAbsentValue]:
        if self.has_member(f"{member}_sec") and self.has_member(f"{member}_nsec"):
            # kernels >= 6.11 it's i_*_sec -> time64_t and i_*_nsec -> u32
            # Ref Linux commit 3aa63a569c64e708df547a8913c84e64a06e7853
            return conversion.unixtime_to_datetime(
                self.member(f"{member}_sec") + self.has_member(f"{member}_nsec") / 1e9
            )
        elif self.has_member(f"__{member}"):
            # 6.6 <= kernels < 6.11 it's a timespec64
            # Ref Linux commit 13bc24457850583a2e7203ded05b7209ab4bc5ef / 12cd44023651666bd44baa36a5c999698890debb
            return self.member(f"__{member}").to_datetime()
        elif self.has_member(member):
            # In kernels < 6.6 it's a timespec64 or timespec
            return self.member(member).to_datetime()
        else:
            raise exceptions.VolatilityException(
                "Unsupported kernel inode type implementation"
            )

    def get_access_time(self) -> datetime.datetime:
        """Returns the inode's last access time
        This is updated when inode contents are read

        Returns:
            A datetime with the inode's last access time
        """
        return self._time_member_to_datetime("i_atime")

    def get_modification_time(self) -> datetime.datetime:
        """Returns the inode's last modification time
        This is updated when the inode contents change

        Returns:
            A datetime with the inode's last data modification time
        """

        return self._time_member_to_datetime("i_mtime")

    def get_change_time(self) -> datetime.datetime:
        """Returns the inode's last change time
        This is updated when the inode metadata changes

        Returns:
            A datetime with the inode's last change time
        """
        return self._time_member_to_datetime("i_ctime")

    def get_file_mode(self) -> str:
        """Returns the inode's file mode as string of the form '-rwxrwxrwx'.

        Returns:
            The inode's file mode string
        """
        return stat.filemode(self.i_mode)

    def get_pages(self) -> Iterable[interfaces.objects.ObjectInterface]:
        """Gets the inode's cached pages

        Yields:
            The inode's cached pages
        """
        if not self.i_size:
            return

        if not (
            self.i_mapping
            and self.i_mapping.is_readable()
            and self.i_mapping.nrpages > 0
        ):
            return

        page_cache = linux.PageCache(
            context=self._context,
            kernel_module_name="kernel",
            page_cache=self.i_mapping.dereference(),
        )

        yield from page_cache.get_cached_pages()

    def get_contents(self) -> Iterable[Tuple[int, bytes]]:
        """Get the inode cached pages from the page cache

        Yields:
            page_index (int): The page index in the Tree. File offset is page_index * PAGE_SIZE.
            page_content (bytes): The page content
        """
        for page_obj in self.get_pages():
            if page_obj.mapping != self.i_mapping:
                vollog.warning(
                    f"Cached page at {page_obj.vol.offset:#x} has a mismatched address space with the inode. Skipping page"
                )
                continue
            page_index = int(page_obj.index)
            page_content = page_obj.get_content()
            if page_content:
                yield page_index, page_content


class address_space(objects.StructType):
    @property
    def i_pages(self):
        """Returns the appropriate member containing the page cache tree"""
        if self.has_member("i_pages"):
            # Kernel >= 4.17 b93b016313b3ba8003c3b8bb71f569af91f19fc7
            return self.member("i_pages")
        elif self.has_member("page_tree"):
            # Kernel < 4.17
            return self.member("page_tree")

        raise exceptions.VolatilityException("Unsupported page cache tree")


class page(objects.StructType):
    def is_valid(self) -> bool:
        if self.mapping and not self.mapping.is_readable():
            return False

        if self.to_paddr() < 0:
            return False

        return True

    @functools.cached_property
    def pageflags_enum(self) -> Dict:
        """Returns 'pageflags' enumeration key/values

        Returns:
            A dictionary with the pageflags enumeration key/values
        """
        try:
            pageflags_enum = self._context.symbol_space.get_enumeration(
                self.get_symbol_table_name() + constants.BANG + "pageflags"
            ).choices
        except exceptions.SymbolError:
            vollog.debug(
                "Unable to find pageflags enum. This can happen in kernels < 2.6.26 or wrong ISF"
            )
            # set to empty dict to show that the enum was not found, and so shouldn't be searched for again
            pageflags_enum = {}

        return pageflags_enum

    @functools.cached_property
    def _intel_vmemmap_start(self) -> int:
        """Determine the start of the struct page array, for Intel systems.

        Returns:
            int: vmemmap_start address
        """
        vmlinux = linux.LinuxUtilities.get_module_from_volobj_type(self._context, self)
        vmlinux_layer = vmlinux.context.layers[vmlinux.layer_name]

        vmemmap_start = None
        if vmlinux.has_symbol("mem_section"):
            # SPARSEMEM_VMEMMAP physical memory model: memmap is virtually contiguous
            if vmlinux.has_symbol("vmemmap_base"):
                # CONFIG_DYNAMIC_MEMORY_LAYOUT - KASLR kernels >= 4.9
                vmemmap_start = vmlinux.object_from_symbol("vmemmap_base")
            else:
                # !CONFIG_DYNAMIC_MEMORY_LAYOUT
                if vmlinux_layer._maxvirtaddr < 57:
                    # 4-Level paging -> VMEMMAP_START = __VMEMMAP_BASE_L4
                    vmemmap_base_l4 = 0xFFFFEA0000000000
                    vmemmap_start = vmemmap_base_l4
                else:
                    # 5-Level paging -> VMEMMAP_START = __VMEMMAP_BASE_L5
                    # FIXME: Once 5-level paging is supported, uncomment the following lines and remove the exception
                    # vmemmap_base_l5 = 0xFFD4000000000000
                    # vmemmap_start = vmemmap_base_l5
                    raise exceptions.VolatilityException(
                        "5-level paging is not yet supported"
                    )

        elif vmlinux.has_symbol("mem_map"):
            # FLATMEM physical memory model, typically 32bit
            vmemmap_start = vmlinux.object_from_symbol("mem_map")

        elif vmlinux.has_symbol("node_data"):
            raise exceptions.VolatilityException("NUMA systems are not yet supported")
        else:
            raise exceptions.VolatilityException("Unsupported Linux memory model")

        if not vmemmap_start:
            raise exceptions.VolatilityException(
                "Something went wrong, we shouldn't be here"
            )

        return vmemmap_start

    def _intel_to_paddr(self) -> int:
        """Converts a page's virtual address to its physical address using the current Intel memory model.

        Returns:
            int: page physical address
        """
        vmlinux = linux.LinuxUtilities.get_module_from_volobj_type(self._context, self)
        vmlinux_layer = vmlinux.context.layers[vmlinux.layer_name]
        pagec = vmlinux_layer.canonicalize(self.vol.offset)
        pfn = (pagec - self._intel_vmemmap_start) // vmlinux.get_type("page").size
        page_paddr = pfn * vmlinux_layer.page_size

        return page_paddr

    def to_paddr(self) -> int:
        """Converts a page's virtual address to its physical address using the current CPU memory model.

        Returns:
            int: page physical address
        """
        vmlinux = linux.LinuxUtilities.get_module_from_volobj_type(self._context, self)
        vmlinux_layer = vmlinux.context.layers[vmlinux.layer_name]
        if isinstance(vmlinux_layer, intel.Intel):
            page_paddr = self._intel_to_paddr()
        else:
            raise exceptions.LayerException(
                f"Architecture {type(vmlinux_layer)} vmemmap_start calculation isn't currently supported."
            )

        return page_paddr

    def get_content(self) -> Union[bytes, None]:
        """Returns the page content

        Returns:
            The page content
        """
        vmlinux = linux.LinuxUtilities.get_module_from_volobj_type(self._context, self)
        vmlinux_layer = vmlinux.context.layers[vmlinux.layer_name]
        physical_layer_name = self._context.layers[self.vol.layer_name].config.get(
            "memory_layer", self.vol.layer_name
        )
        physical_layer = self._context.layers[physical_layer_name]
        page_paddr = self.to_paddr()
        if not page_paddr:
            return None

        if not physical_layer.is_valid(page_paddr, length=vmlinux_layer.page_size):
            vollog.debug(
                "Unable to read page 0x%x content at 0x%x", self.vol.offset, page_paddr
            )
            return None

        return physical_layer.read(page_paddr, vmlinux_layer.page_size)

    def get_flags_list(self) -> List[str]:
        """Returns a list of page flags

        Returns:
            List of page flags
        """
        flags = []
        for name, value in self.pageflags_enum.items():
            if self.flags & (1 << value) != 0:
                flags.append(name)

        return flags


class IDR(objects.StructType):
    IDR_BITS = 8
    IDR_MASK = (1 << IDR_BITS) - 1
    INT_SIZE = 4
    MAX_IDR_SHIFT = INT_SIZE * 8 - 1
    MAX_IDR_BIT = 1 << MAX_IDR_SHIFT

    def idr_max(self, num_layers: int) -> int:
        """Returns the maximum ID which can be allocated given idr::layers

        Args:
            num_layers: Number of layers

        Returns:
            Maximum ID for a given number of layers
        """
        # Kernel < 4.17
        bits = min([self.INT_SIZE, num_layers * self.IDR_BITS, self.MAX_IDR_SHIFT])

        return (1 << bits) - 1

    def idr_find(self, idr_id: int) -> Optional[int]:
        """Finds an ID within the IDR data structure.
        Based on idr_find_slowpath(), 3.9 <= Kernel < 4.11
        Args:
            idr_id: The IDR lookup ID

        Returns:
            A pointer to the given ID element
        """
        vmlinux = linux.LinuxUtilities.get_module_from_volobj_type(self._context, self)
        if not vmlinux.get_type("idr_layer").has_member("layer"):
            vollog.info(
                "Unsupported IDR implementation, it should be a very very old kernel, probabably < 2.6"
            )
            return None

        if idr_id < 0:
            return None

        idr_layer = self.top
        if not idr_layer:
            return None

        n = (idr_layer.layer + 1) * self.IDR_BITS

        if idr_id > self.idr_max(idr_layer.layer + 1):
            return None

        assert n != 0

        while n > 0 and idr_layer:
            n -= self.IDR_BITS
            assert n == idr_layer.layer * self.IDR_BITS
            idr_layer = idr_layer.ary[(idr_id >> n) & self.IDR_MASK]

        return idr_layer

    def _old_kernel_get_entries(self) -> Iterable[int]:
        # Kernels < 4.11
        cur = self.cur
        total = next_id = 0
        while next_id < cur:
            entry = self.idr_find(next_id)
            if entry:
                yield entry
                total += 1

            next_id += 1

    def _new_kernel_get_entries(self) -> Iterable[int]:
        # Kernels >= 4.11
        id_storage = linux.IDStorage.choose_id_storage(
            self._context, kernel_module_name="kernel"
        )
        yield from id_storage.get_entries(root=self.idr_rt)

    def get_entries(self) -> Iterable[int]:
        """Walks the IDR and yield a pointer associated with each element.

        Args:
            in_use (int, optional): _description_. Defaults to 0.

        Yields:
            A pointer associated with each element.
        """
        if self.has_member("idr_rt"):
            # Kernels >= 4.11
            get_entries_func = self._new_kernel_get_entries
        else:
            # Kernels < 4.11
            get_entries_func = self._old_kernel_get_entries

        yield from get_entries_func()


class rb_root(objects.StructType):
    def _walk_nodes(
        self, root_node: interfaces.objects.ObjectInterface
    ) -> Iterator[int]:
        """Traverses the Red-Black tree from the root node and yields a pointer to each
        node in this tree.

        Args:
            root_node: A Red-Black tree node pointer from which to start descending

        Yields:
            A pointer to every node descending from the specified root node
        """
        if not (root_node and root_node.is_readable()):
            return

        yield root_node
        yield from self._walk_nodes(root_node.rb_left)
        yield from self._walk_nodes(root_node.rb_right)

    def get_nodes(self) -> Iterator[int]:
        """Yields a pointer to each node in the Red-Black tree

        Yields:
            A pointer to every node in the Red-Black tree
        """

        yield from self._walk_nodes(root_node=self.rb_node)


class scatterlist(objects.StructType):
    SG_CHAIN = 0x01
    SG_END = 0x02
    SG_PAGE_LINK_MASK = SG_CHAIN | SG_END

    def _sg_flags(self) -> int:
        return self.page_link & self.SG_PAGE_LINK_MASK

    def _sg_is_chain(self) -> int:
        return self._sg_flags() & self.SG_CHAIN

    def _sg_is_last(self) -> int:
        return self._sg_flags() & self.SG_END

    def _sg_chain_ptr(self) -> int:
        """Clears the last two bits basically."""
        return self.page_link & ~self.SG_PAGE_LINK_MASK

    def _sg_dma_len(self) -> int:
        # Depends on CONFIG_NEED_SG_DMA_LENGTH
        if self.has_member("dma_length"):
            return self.dma_length
        return self.length

    def _get_sg_max_single_alloc(self) -> int:
        """Based on kernel's SG_MAX_SINGLE_ALLOC.

        Doc. from kernel source :
            * Maximum number of entries that will be allocated in one piece, if
            * a list larger than this is required then chaining will be utilized.
        """
        return self._context.layers[self.vol.layer_name].page_size // self.vol.size

    def _sg_next(self) -> Optional[interfaces.objects.ObjectInterface]:
        """Get the next scatterlist struct from the list.
        Based on kernel's sg_next.

        Doc. from kernel source :
            * Notes on SG table design.
            *
            * We use the unsigned long page_link field in the scatterlist struct to place
            * the page pointer AND encode information about the sg table as well. The two
            * lower bits are reserved for this information.
            *
            * If bit 0 is set, then the page_link contains a pointer to the next sg
            * table list. Otherwise the next entry is at sg + 1.
            *
            * If bit 1 is set, then this sg entry is the last element in a list.
        """
        if self._sg_is_last():
            return None

        if self._sg_is_chain():
            next_address = self._sg_chain_ptr()
        else:
            next_address = self.vol.offset + self.vol.size

        sg = self._context.object(
            self.get_symbol_table_name() + constants.BANG + "scatterlist",
            self.vol.layer_name,
            next_address,
        )
        return sg

    def for_each_sg(self) -> Optional[Iterator[interfaces.objects.ObjectInterface]]:
        """Iterate over each struct in the scatterlist."""
        sg = self
        sg_max_single_alloc = self._get_sg_max_single_alloc()

        # Empty scatterlists protection
        if sg.page_link == 0 and sg._sg_dma_len() == 0 and sg.dma_address == 0:
            return None
        else:
            # Yield itself first
            yield sg

        entries_count = 1
        # entries_count <= sg_max_single_alloc should always be true if the
        # scatterlists were correctly chained.
        while entries_count <= sg_max_single_alloc:
            sg = sg._sg_next()
            if sg is None:
                break
            # Points to a new scatterlist
            elif sg._sg_is_chain():
                entries_count = 0
            else:
                entries_count += 1
                yield sg

    def get_content(
        self,
    ) -> Optional[Iterator[bytes]]:
        """Traverse a scatterlist to gather content located at each
        dma_address position.

        Returns:
            An iterator of bytes
        """
        # Either "physical" is layer-1 because this is a module layer, or "physical" is the current layer
        physical_layer_name = self._context.layers[self.vol.layer_name].config.get(
            "memory_layer", self.vol.layer_name
        )
        physical_layer = self._context.layers[physical_layer_name]
        for sg in self.for_each_sg():
            yield from physical_layer.read(sg.dma_address, sg._sg_dma_len())


class latch_tree_root(objects.StructType):
    """Latched RB-trees implementation"""

    @functools.cached_property
    def _vmlinux(self):
        return linux.LinuxUtilities.get_module_from_volobj_type(self._context, self)

    @functools.lru_cache
    def _get_type_cached(self, name):
        return self._vmlinux.get_type(name)

    def _get_lt_node_from_rb_node(
        self, rb_node, index
    ) -> Optional[interfaces.objects.ObjectInterface]:
        """Gets the latch tree node from the RBTree node.
        Based on __lt_from_rb()
        """
        # Unfortunately, we cannot use our LinuxUtilities.container_of() here, since the
        # member is indexed by the 'index' variable:
        #   ltn = container_of(node, struct latch_tree_node, node[idx])
        pointer_size = self._get_type_cached("pointer").size
        type_dec = self._get_type_cached("latch_tree_node")
        member_offset = type_dec.relative_child_offset("node") + index * pointer_size
        container_addr = rb_node.vol.offset - member_offset

        return self._vmlinux.object(
            object_type="latch_tree_node", offset=container_addr, absolute=True
        )

    def find(
        self, key: int, comp_function: Callable
    ) -> Optional[interfaces.objects.ObjectInterface]:
        """Returns a pointer to the node matching key or None.

        Based on latch_tree_find() and __lt_find()

        Args:
            key (int): Typically an address
            comp_function: Callback comparison function to provide the order between the
                search key and an element. It's works like the kernel's latch_tree_ops::comp
                i.e.: comp_function(key, latch_tree_node)

        Returns:
            latch_tree_node: A pointer to the node matching key or None.
        """
        # latch_tree_root >= 4.2 ade3f510f93a5613b672febe88eff8ea7f1c63b7

        # Use the lowest sequence bit as an index for picking which data copy to read
        if self.seq.has_member("seqcount"):
            # kernels >= 5.10 0c9794c8b6781eb7dad8e19b78c5d4557790597a
            sequence = self.seq.seqcount.sequence
        elif self.seq.has_member("sequence"):
            # 4.2 <= kernel < 5.10
            sequence = self.seq.sequence
        else:
            raise AttributeError("Unsupported sequence type implementation")

        idx = sequence & 1

        rb_node_ptr = self.tree[idx].rb_node
        while rb_node_ptr and rb_node_ptr.is_readable():
            rb_node = rb_node_ptr.dereference()
            lt_node = self._get_lt_node_from_rb_node(rb_node, idx)
            c = comp_function(key, lt_node)
            if c is None:
                return None
            elif c < 0:
                rb_node_ptr = rb_node.rb_left
            elif c > 0:
                rb_node_ptr = rb_node.rb_right
            else:
                return lt_node

        return None


class kernel_symbol(objects.StructType):

    def _offset_to_ptr(self, off) -> int:
        layer = self._context.layers[self.vol.layer_name]
        long_mask = (1 << layer.bits_per_register) - 1
        return (self.vol.offset + off) & long_mask

    def _do_get_name(self) -> str:
        if self.has_member("name_offset"):
            # kernel >= 4.19 and CONFIG_HAVE_ARCH_PREL32_RELOCATIONS=y
            # See 7290d58095712a89f845e1bca05334796dd49ed2
            name_offset = self._offset_to_ptr(self.name_offset)
        elif self.has_member("name"):
            # kernel < 4.19 or CONFIG_HAVE_ARCH_PREL32_RELOCATIONS=n
            name_offset = self.member("name")
        else:
            raise AttributeError("Unsupported kernel_symbol type implementation")

        layer = self._context.layers[self.vol.layer_name]
        name_bytes = layer.read(name_offset, linux_constants.KSYM_NAME_LEN)

        idx = name_bytes.find(b"\x00")
        if idx != -1:
            name_bytes = name_bytes[:idx]

        return name_bytes.decode("utf-8", errors="ignore")

    def get_name(self) -> Optional[str]:
        try:
            return self._do_get_name()
        except exceptions.InvalidAddressException:
            return None

    def _do_get_value(self) -> int:
        if self.has_member("value_offset"):
            # kernel >= 4.19 and CONFIG_HAVE_ARCH_PREL32_RELOCATIONS=y
            # See 7290d58095712a89f845e1bca05334796dd49ed2
            return self._offset_to_ptr(self.value_offset)
        elif self.has_member("value"):
            # kernel < 4.19 or CONFIG_HAVE_ARCH_PREL32_RELOCATIONS=n
            return self.member("value")

        raise AttributeError("Unsupported kernel_symbol type implementation")

    def get_value(self) -> Optional[int]:
        try:
            return self._do_get_value()
        except exceptions.InvalidAddressException:
            return None

    def _do_get_namespace(self) -> str:
        if self.has_member("namespace_offset"):
            # kernel >= 4.19 and CONFIG_HAVE_ARCH_PREL32_RELOCATIONS=y
            # See 7290d58095712a89f845e1bca05334796dd49ed2
            namespace_offset = self._offset_to_ptr(self.namespace_offset)
        elif self.has_member("namespace"):
            # kernel < 4.19 or CONFIG_HAVE_ARCH_PREL32_RELOCATIONS=n
            namespace_offset = self.member("namespace")
        else:
            raise AttributeError("Unsupported kernel_symbol type implementation")

        layer = self._context.layers[self.vol.layer_name]
        namespace_bytes = layer.read(namespace_offset, linux_constants.KSYM_NAME_LEN)

        idx = namespace_bytes.find(b"\x00")
        if idx != -1:
            namespace_bytes = namespace_bytes[:idx]

        return namespace_bytes.decode("utf-8", errors="ignore")

    def get_namespace(self) -> Optional[str]:
        try:
            return self._do_get_namespace()
        except exceptions.InvalidAddressException:
            return None


class module_sect_attr(objects.StructType):
    def get_name(self) -> Optional[str]:
        """
        Performs careful extraction of the section name
        The `name` member has changed type and meaning over time
        It also was present even in cases with `mattr` present, which
        holds the name the kernel uses
        """
        if hasattr(self, "battr"):
            try:
                return utility.pointer_to_string(self.battr.attr.name, count=32)
            except exceptions.InvalidAddressException:
                # if battr is present then its name attribute needs to be valid
                vollog.debug(f"Invalid battr name for section at {self.vol.offset:#x}")
                return None

        elif self.name.vol.type_name == "array":
            try:
                return utility.array_to_string(self.name, count=32)
            except exceptions.InvalidAddressException:
                # specifically do not return here to give `mattr` a chance
                vollog.debug(f"Invalid direct name for section at {self.vol.offset:#x}")

        elif self.name.vol.type_name == "pointer":
            try:
                return utility.pointer_to_string(self.name, count=32)
            except exceptions.InvalidAddressException:
                # specifically do not return here to give `mattr` a chance
                vollog.debug(
                    f"Invalid pointer name for section at {self.vol.offset:#x}"
                )

        # if everything else failed...
        if hasattr(self, "mattr"):
            try:
                return utility.pointer_to_string(self.mattr.attr.name, count=32)
            except exceptions.InvalidAddressException:
                vollog.debug(
                    f"Unresolvable name for for section at {self.vol.offset:#x}"
                )

        return None
