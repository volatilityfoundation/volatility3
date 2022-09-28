import logging
from typing import Any, Callable, Dict, List, Tuple

import unicorn

from volatility3.cli.volshell import VolshellPlugin
from volatility3.cli.volshell.generic import VolshellShellPlugin
from volatility3.framework import exceptions
from volatility3.framework.layers import intel

vollog = logging.getLogger(__name__)


# TODO: Establish appropriate paging and setup CR3 and pass through the physical layer


class VolshellUnicorn(VolshellPlugin):
    def __init__(self, parent: VolshellShellPlugin):
        super().__init__(parent)

        vollog.info("Welcome to the unicorn volshell plugin")

        self._parent = parent
        self._unicorn = None
        # self._physical_layer = None
        self.change_layer(self._parent.current_layer)

    def construct_locals(self) -> List[Tuple[List[str], Any]]:
        return [(['uc_run'], self._uc_run),
                (['uc_regread'], self._uc_reg_read),
                (['uc_regwrite'], self._uc_reg_write),
                (['unicorn'], self.unicorn),
                (['cl', 'change_layer'], self.change_layer)]

    def _uc_run(self, start_address: int, stop_address: int, timeout: int = None, count: int = None):
        """Runs the emulator from start_address to stop_address"""
        kwargs = {}
        if count is not None:
            kwargs['count'] = count
        if timeout is not None:
            kwargs['timeout'] = timeout
        # Doesn't like None for arguments that aren't there, hence the kwargs magic
        self.unicorn.emu_start(start_address, stop_address, **kwargs)

    def _uc_reg_read(self, register: int):
        """Gets a specific register"""
        return self.unicorn.reg_read(register)

    def _uc_reg_write(self, register: int, value: int):
        """Sets a specific register to a value"""
        self.unicorn.reg_write(register, value)

    @property
    def context(self):
        return self._parent.context

    @property
    def hooks(self) -> Dict[int, Callable]:
        return {unicorn.UC_HOOK_MEM_FETCH: self.mem_unmapped,
                unicorn.UC_HOOK_MEM_UNMAPPED: self.mem_unmapped}

    # def _find_physical_memory_layer(self):
    #     """Rudimentary method to find the physical layer"""
    #     current_layer = self.context.layers[self._parent.current_layer]
    #     while isinstance(current_layer, intel.Intel):
    #         checking = current_layer
    #         for dependency in current_layer.dependencies:
    #             dependency_layer = self.context.layers[dependency]
    #             if isinstance(dependency_layer, intel.Intel):
    #                 current_layer = dependency_layer
    #                 break
    #         # If we haven't gone down a layer, then we're done
    #         if checking == current_layer:
    #             break
    #     self._physical_layer = self.context.layers[self._parent.current_layer]

    def mem_unmapped(self, uc, access, address, size, value, user_data):
        """Map in any memory misses"""
        print(f"Memory failed: {access} {address:x} {size:x}")

        layer = self.context.layers[self._parent.current_layer]

        page_start = address
        page_end = address + size + layer.page_size
        page_start ^= page_start & (layer.page_size - 1)
        page_end ^= page_end & (layer.page_size - 1)

        try:
            # Make sure to read from the right layer based on
            data = layer.read(page_start, page_end - page_start)
            # Map the whole page data, since accesses after won't fail once the page is mapped
            uc.mem_map(page_start, page_end - page_start)
            uc.mem_write(page_start, data)
        except exceptions.InvalidAddressException:
            vollog.debug(f"Unicorn address access failed: {address:x}")
            return False
        return True

    @property
    def unicorn(self) -> unicorn.Uc:
        return self._unicorn

    def change_layer(self, layer_name: str):
        """Changes the current default layer"""
        self._parent.change_layer(layer_name)
        # self._find_physical_memory_layer()
        arch, mode = None, None

        # Setup the DTB and appropriate paging
        layer = self.context.layers[self._parent.current_layer]
        # Check the layer for architecture, set up the Unicorn machine
        if isinstance(layer, intel.Intel):
            arch = unicorn.UC_ARCH_X86
            mode = unicorn.UC_MODE_32
            # self.register_names = [name for name in dir(unicorn.x86_const) if name.startswith('UC_X86_REG_')]
        if isinstance(layer, intel.Intel32e):
            mode = unicorn.UC_MODE_64
            arch = unicorn.UC_ARCH_X86
            # self.register_names = [name for name in dir(unicorn.x86_const) if name.startswith('UC_X86_REG_')]

        # Establish the emulator
        if arch is None and mode is None:
            vollog.warning(f"Layer {self._parent.current_layer} is not a supported architecture")
            return

        self._unicorn = unicorn.Uc(arch, mode)

        if isinstance(layer, intel.Intel):

            # TODO: Turn on proper mapping
            # TODO: Figure out whether memory failures happen on lookups

            # The following seems not to work
            # dtb = layer.config.get('page_map_offset', 0)
            # if dtb:
            #     # Write the DTB
            #     self._unicorn.reg_write(UC_X86_REG_CR3, dtb)
            #     # Don't use proper mapping because we can't catch lookup failures in page maps
            #     cr0 = self._unicorn.reg_read(UC_X86_REG_CR0)
            #     self._unicorn.reg_write(UC_X86_REG_CR0, cr0 & 0x80000000)

            # Apply hooks (particularly memory access failures)
            for hook in self.hooks:
                self.unicorn.hook_add(hook, self.hooks[hook])
        else:
            vollog.warning("Chosen layer is not an intel layer, unicorn registers not set")
