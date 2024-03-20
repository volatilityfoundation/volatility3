# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
import logging
from typing import Iterator, Any, Iterable, List, Tuple, Set

from volatility3.framework import interfaces, objects, exceptions, constants
from volatility3.framework.symbols import intermed
from volatility3.framework.symbols.mac import extensions
from volatility3.framework.interfaces.configuration import path_join

vollog = logging.getLogger(__name__)


class MacKernelIntermedSymbols(intermed.IntermediateSymbolTable):
    provides = {"type": "interface"}

    def __init__(
        self, do_i386_kernel_cache_unslide: bool = True, *args, **kwargs
    ) -> None:
        super().__init__(*args, **kwargs)

        self.set_type_class("proc", extensions.proc)
        self.set_type_class("fileglob", extensions.fileglob)
        self.set_type_class("vnode", extensions.vnode)
        self.set_type_class("vm_map_entry", extensions.vm_map_entry)
        self.set_type_class("vm_map_object", extensions.vm_map_object)
        self.set_type_class("socket", extensions.socket)
        self.set_type_class("inpcb", extensions.inpcb)
        self.set_type_class("ifnet", extensions.ifnet)
        self.set_type_class("sockaddr_dl", extensions.sockaddr_dl)
        self.set_type_class("sockaddr", extensions.sockaddr)
        self.set_type_class("sysctl_oid", extensions.sysctl_oid)
        self.set_type_class("kauth_scope", extensions.kauth_scope)
        # https://developer.apple.com/documentation/kernel/queue_head_t
        self.set_type_class("queue_entry", extensions.queue_entry)
        self.optional_set_type_class("queue_head_t", extensions.queue_entry)
        # If a kernel layer exists, we want to check if an MH_FILESET kernel cache
        # was detected. If so, we need to unslide the concerned kernel symbols.
        config_path_without_last_part = self.config_path.rsplit(
            self.context.config.separator, 1
        )[0]
        kernel_layer_config_path = path_join(
            config_path_without_last_part, "layer_name"
        )
        if (
            self.context.config.get(
                path_join(kernel_layer_config_path, "mh_fileset_kernel_cache_check")
            )
            and do_i386_kernel_cache_unslide
        ):
            vm_kernel_slide = self.context.config[
                path_join(kernel_layer_config_path, "vm_kernel_slide")
            ]
            kaslr_shift = self.context.config[
                path_join(kernel_layer_config_path, "kernel_virtual_offset")
            ]
            kernel_start = self.context.config[
                path_join(kernel_layer_config_path, "kernel_start")
            ]
            kernel_end = self.context.config[
                path_join(kernel_layer_config_path, "kernel_end")
            ]
            self.i386_kernel_cache_unslide_symbols(
                vm_kernel_slide, kaslr_shift, kernel_start, kernel_end
            )

    def i386_kernel_cache_unslide_symbols(
        self,
        vm_kernel_slide: int,
        kaslr_shift: int,
        kernel_start: int,
        kernel_end: int,
    ) -> Tuple[int, int]:
        """
        If the MH_FILESET KernelCache support is ON, header addresses in all mach-o segments and sections
        of the MH_FILESET are slid by a specific offset. This is problematic, as some kernel symbols, typically
        contained in an external ISF file, won't be correctly readable with a sole KASLR shift.
        To circumvent this, we unslide every symbol address determined to be part of the KernelCache
        in a position reachable by KASLR shift. This only affects the current symbol table.
        """

        # This is equivalent to the "slide" value from :
        # https://github.com/apple-open-source/macos/blob/14.3/xnu/osfmk/i386/i386_init.c#L621
        slide = vm_kernel_slide - kaslr_shift
        if slide == 0:
            return 0, 0
        """
        Addresses slid by i386_slide_and_rebase_image's slide are now in the kernelcache.
        We want each symbol address to be slidable by aslr_slide, for the global context.
        In this sense, we will slide concerned addresses references back to their original positions.
        """
        # Check if a symbol, slid by vm_kernel_slide, is located in the kernel _TEXT boundaries.
        # Using symbols_as_dict method (fewer function calls) and a one liner offers a huge performance boost
        to_slide = []
        [
            to_slide.append((sym_name, sym["address"]))
            for sym_name, sym in self.symbols_as_dict.items()
            if kernel_start <= sym["address"] + vm_kernel_slide <= kernel_end
        ]
        [
            self.update_symbol_address(sym_name, sym_address + slide)
            for sym_name, sym_address in to_slide
        ]
        to_slide_len = len(to_slide)
        if to_slide_len != 0:
            vollog.log(
                constants.LOGLEVEL_VVVV,
                f"{to_slide_len} symbols located in the MH_FILESET KernelCache were rebased with offset {hex(slide)}, to be reachable by KASLR shift.",
            )
        return slide, to_slide_len


class MacUtilities(interfaces.configuration.VersionableInterface):
    """Class with multiple useful mac functions."""

    """
    Version History:
    1.1.0 -> added walk_list_head API
    1.2.0 -> added walk_slist API
    1.3.0 -> add parameter to lookup_module_address to pass kernel module name
    """
    _version = (1, 3, 0)
    _required_framework_version = (2, 0, 0)

    @classmethod
    def mask_mods_list(
        cls,
        context: interfaces.context.ContextInterface,
        layer_name: str,
        mods: Iterator[Any],
    ) -> List[Tuple[interfaces.objects.ObjectInterface, Any, Any]]:
        """
        A helper function to mask the starting and end address of kernel modules
        """
        mask = context.layers[layer_name].address_mask

        return [
            (
                objects.utility.array_to_string(mod.name),
                mod.address & mask,
                (mod.address & mask) + mod.size,
            )
            for mod in mods
        ]

    @classmethod
    def generate_kernel_handler_info(
        cls,
        context: interfaces.context.ContextInterface,
        layer_name: str,
        kernel,  # ikelos - how to type this??
        mods_list: Iterator[Any],
    ):
        try:
            start_addr = kernel.object_from_symbol("vm_kernel_stext")
        except exceptions.SymbolError:
            start_addr = kernel.object_from_symbol("stext")

        try:
            end_addr = kernel.object_from_symbol("vm_kernel_etext")
        except exceptions.SymbolError:
            end_addr = kernel.object_from_symbol("etext")

        mask = context.layers[layer_name].address_mask

        start_addr = start_addr & mask
        end_addr = end_addr & mask

        return [("__kernel__", start_addr, end_addr)] + MacUtilities.mask_mods_list(
            context, layer_name, mods_list
        )

    @classmethod
    def lookup_module_address(
        cls,
        context: interfaces.context.ContextInterface,
        handlers: Iterator[Any],
        target_address,
        kernel_module_name: str = None,
    ):
        mod_name = "UNKNOWN"
        symbol_name = "N/A"

        module_shift = 0
        if kernel_module_name:
            module = context.modules[kernel_module_name]
            module_shift = module.offset

        for name, start, end in handlers:
            if start <= target_address <= end:
                mod_name = name
                if name == "__kernel__":
                    symbols = list(
                        context.symbol_space.get_symbols_by_location(
                            target_address - module_shift
                        )
                    )

                    if len(symbols) > 0:
                        symbol_name = (
                            str(symbols[0].split(constants.BANG)[1])
                            if constants.BANG in symbols[0]
                            else str(symbols[0])
                        )

                break

        return mod_name, symbol_name

    @classmethod
    def files_descriptors_for_process(
        cls,
        context: interfaces.context.ContextInterface,
        symbol_table_name: str,
        task: interfaces.objects.ObjectInterface,
    ):
        """Creates a generator for the file descriptors of a process

        Args:
            symbol_table_name: The name of the symbol table associated with the process
            context:
            task: The process structure to enumerate file descriptors from

        Return:
            A 3 element tuple is yielded for each file descriptor:
            1) The file's object
            2) The path referenced by the descriptor.
                The path is either empty, the full path of the file in the file system, or the formatted name for sockets, pipes, etc.
            3) The file descriptor number
        """

        try:
            num_fds = task.p_fd.fd_lastfile
        except exceptions.InvalidAddressException:
            num_fds = 1024

        try:
            nfiles = task.p_fd.fd_nfiles
        except exceptions.InvalidAddressException:
            nfiles = 1024

        if nfiles > num_fds:
            num_fds = nfiles

        if num_fds > 4096:
            num_fds = 1024

        file_type = symbol_table_name + constants.BANG + "fileproc"

        try:
            table_addr = task.p_fd.fd_ofiles.dereference()
        except exceptions.InvalidAddressException:
            return None

        fds = objects.utility.array_of_pointers(
            table_addr, count=num_fds, subtype=file_type, context=context
        )

        for fd_num, f in enumerate(fds):
            if f != 0:
                try:
                    ftype = f.f_fglob.get_fg_type()
                except exceptions.InvalidAddressException:
                    continue

                if ftype == "VNODE":
                    vnode = f.f_fglob.fg_data.dereference().cast("vnode")
                    path = vnode.full_path()
                elif ftype:
                    path = f"<{ftype.lower()}>"

                yield f, path, fd_num

    @classmethod
    def _walk_iterable(
        cls,
        queue: interfaces.objects.ObjectInterface,
        list_head_member: str,
        list_next_member: str,
        next_member: str,
        max_elements: int = 4096,
    ) -> Iterable[interfaces.objects.ObjectInterface]:
        seen: Set[int] = set()

        try:
            current = queue.member(attr=list_head_member)
        except exceptions.InvalidAddressException:
            return None

        while current:
            if current.vol.offset in seen:
                break

            seen.add(current.vol.offset)

            if len(seen) == max_elements:
                break

            if current.is_readable():
                yield current

            try:
                current = current.member(attr=next_member).member(attr=list_next_member)
            except exceptions.InvalidAddressException:
                break

    @classmethod
    def walk_tailq(
        cls,
        queue: interfaces.objects.ObjectInterface,
        next_member: str,
        max_elements: int = 4096,
    ) -> Iterable[interfaces.objects.ObjectInterface]:
        for element in cls._walk_iterable(
            queue, "tqh_first", "tqe_next", next_member, max_elements
        ):
            yield element

    @classmethod
    def walk_list_head(
        cls,
        queue: interfaces.objects.ObjectInterface,
        next_member: str,
        max_elements: int = 4096,
    ) -> Iterable[interfaces.objects.ObjectInterface]:
        for element in cls._walk_iterable(
            queue, "lh_first", "le_next", next_member, max_elements
        ):
            yield element

    @classmethod
    def walk_slist(
        cls,
        queue: interfaces.objects.ObjectInterface,
        next_member: str,
        max_elements: int = 4096,
    ) -> Iterable[interfaces.objects.ObjectInterface]:
        for element in cls._walk_iterable(
            queue, "slh_first", "sle_next", next_member, max_elements
        ):
            yield element
