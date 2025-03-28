# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
"""A module containing a plugin that checks the system call table for hooks."""
import contextlib
import logging
from typing import List

from volatility3.framework import constants, exceptions, interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.interfaces import plugins
from volatility3.framework.renderers import format_hints

vollog = logging.getLogger(__name__)

try:
    import capstone

    has_capstone = True
except ImportError:
    has_capstone = False


class Check_syscall(plugins.PluginInterface):
    """Check system call table for hooks."""

    _required_framework_version = (2, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Linux kernel",
                architectures=["Intel32", "Intel64"],
            ),
        ]

    def _get_table_size_next_symbol(self, table_addr, ptr_sz, vmlinux):
        """Returns the size of the table based on the next symbol."""
        ret = 0

        symbol_list = []
        for sn in vmlinux.symbols:
            with contextlib.suppress(exceptions.SymbolError):
                # When requesting the symbol from the module, a full resolve is performed
                symbol_list.append((vmlinux.get_symbol(sn).address, sn))
        sorted_symbols = sorted(symbol_list)

        sym_address = 0

        for tmp_sym_address, sym_name in sorted_symbols:
            if tmp_sym_address > table_addr:
                sym_address = tmp_sym_address
                break

        if sym_address > 0:
            ret = int((sym_address - table_addr) / ptr_sz)

        return ret

    def _get_table_size_meta(self, vmlinux):
        """returns the number of symbols that start with __syscall_meta__ this
        is a fast way to determine the number of system calls, but not the most
        accurate."""

        return len(
            [
                sym
                for sym in self.context.symbol_space[vmlinux.symbol_table_name].symbols
                if sym.startswith("__syscall_meta__")
            ]
        )

    def _get_table_info_other(self, table_addr, ptr_sz, vmlinux):
        table_size_meta = self._get_table_size_meta(vmlinux)
        table_size_syms = self._get_table_size_next_symbol(table_addr, ptr_sz, vmlinux)

        sizes = [size for size in [table_size_meta, table_size_syms] if size > 0]

        table_size = min(sizes)

        return table_size

    def _get_table_info_disassembly(self, ptr_sz, vmlinux) -> int:
        """Find the size of the system call table by disassembling functions
        that immediately reference it in their first instruction This is in the
        form 'cmp reg,NR_syscalls'."""
        table_size = 0

        if not has_capstone:
            return table_size

        if ptr_sz == 4:
            syscall_entry_func = "sysenter_do_call"
            mode = capstone.CS_MODE_32
        else:
            syscall_entry_func = "system_call_fastpath"
            mode = capstone.CS_MODE_64

        md = capstone.Cs(capstone.CS_ARCH_X86, mode)

        try:
            func_addr = vmlinux.get_symbol(syscall_entry_func).address
        except exceptions.SymbolError:
            # if we can't find the disassemble function then bail and rely on a different method
            return 0

        vmlinux = self.context.modules[self.config["kernel"]]
        vmlinux_layer = self.context.layers[vmlinux.layer_name]
        try:
            data = vmlinux_layer.read(func_addr, 6)
        except exceptions.InvalidAddressException:
            return 0

        for _address, _size, mnemonic, op_str in md.disasm_lite(data, func_addr):
            if mnemonic == "CMP":
                table_size = int(op_str.split(",")[1].strip()) & 0xFFFF
                break

        return table_size

    def _get_table_info(self, vmlinux, table_name, ptr_sz):
        table_sym = vmlinux.get_symbol(table_name)

        table_size = self._get_table_info_disassembly(ptr_sz, vmlinux)

        if table_size == 0:
            table_size = self._get_table_info_other(table_sym.address, ptr_sz, vmlinux)

            if table_size == 0:
                vollog.error("Unable to get system call table size")
                return 0, 0

        return table_sym.address, table_size

    # TODO - add finding and parsing unistd.h once cached file enumeration is added
    def _generator(self):
        vmlinux = self.context.modules[self.config["kernel"]]

        ptr_sz = vmlinux.get_type("pointer").size
        if ptr_sz == 4:
            table_name = "32bit"
        else:
            table_name = "64bit"

        try:
            table_info = self._get_table_info(vmlinux, "sys_call_table", ptr_sz)
        except exceptions.SymbolError:
            vollog.error("Unable to find the system call table. Exiting.")
            return None

        tables = [(table_name, table_info)]

        # this table is only present on 64 bit systems with 32 bit emulation
        # enabled in order to support 32 bit programs and libraries
        # if the symbol isn't there then the support isn't in the kernel and so we skip it
        try:
            ia32_symbol = vmlinux.get_symbol("ia32_sys_call_table")
        except exceptions.SymbolError:
            ia32_symbol = None

        if ia32_symbol is not None:
            ia32_info = self._get_table_info(vmlinux, "ia32_sys_call_table", ptr_sz)
            tables.append(("32bit", ia32_info))

        for table_name, (tableaddr, tblsz) in tables:
            table = vmlinux.object(
                object_type="array",
                subtype=vmlinux.get_type("pointer"),
                offset=tableaddr,
                count=tblsz,
            )

            for i in range(len(table)):
                try:
                    call_addr = table[i]
                except exceptions.InvalidAddressException:
                    vollog.debug(f"Failed to get system call table entry at index {i}")
                    continue

                symbols = list(vmlinux.get_symbols_by_absolute_location(call_addr))

                if len(symbols) > 0:
                    sym_name = (
                        str(symbols[0].split(constants.BANG)[1])
                        if constants.BANG in symbols[0]
                        else str(symbols[0])
                    )
                else:
                    sym_name = "UNKNOWN"

                yield (
                    0,
                    (
                        format_hints.Hex(tableaddr),
                        table_name,
                        i,
                        format_hints.Hex(call_addr),
                        sym_name,
                    ),
                )

    def run(self):
        return renderers.TreeGrid(
            [
                ("Table Address", format_hints.Hex),
                ("Table Name", str),
                ("Index", int),
                ("Handler Address", format_hints.Hex),
                ("Handler Symbol", str),
            ],
            self._generator(),
        )
