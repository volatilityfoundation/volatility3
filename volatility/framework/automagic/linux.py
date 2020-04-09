# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

import logging
from typing import List, Optional, Tuple, Type

from volatility.framework import interfaces, constants, exceptions, layers
from volatility.framework import symbols, objects
from volatility.framework.automagic import symbol_cache, symbol_finder
from volatility.framework.layers import intel, scanners
from volatility.framework.symbols import linux

vollog = logging.getLogger(__name__)


class LinuxBannerCache(symbol_cache.SymbolBannerCache):
    """Caches the banners found in the Linux symbol files."""

    os = "linux"
    symbol_name = "linux_banner"
    banner_path = constants.LINUX_BANNERS_PATH


class LinuxSymbolFinder(symbol_finder.SymbolFinder):
    """Linux symbol loader based on uname signature strings."""

    banner_config_key = "kernel_banner"
    banner_cache = LinuxBannerCache
    symbol_class = "volatility.framework.symbols.linux.LinuxKernelIntermedSymbols"


class LintelStacker(interfaces.automagic.StackerLayerInterface):
    stack_order = 45

    @classmethod
    def stack(cls,
              context: interfaces.context.ContextInterface,
              layer_name: str,
              progress_callback: constants.ProgressCallback = None) -> Optional[interfaces.layers.DataLayerInterface]:
        """Attempts to identify linux within this layer."""
        # Bail out by default unless we can stack properly
        layer = context.layers[layer_name]
        join = interfaces.configuration.path_join

        # Never stack on top of an intel layer
        # FIXME: Find a way to improve this check
        if isinstance(layer, intel.Intel):
            return None

        linux_banners = LinuxBannerCache.load_banners()
        # If we have no banners, don't bother scanning
        if not linux_banners:
            vollog.info("No Linux banners found - if this is a linux plugin, please check your symbol files location")
            return None

        mss = scanners.MultiStringScanner([x for x in linux_banners if x is not None])
        for _, banner in layer.scan(context = context, scanner = mss, progress_callback = progress_callback):
            dtb = None
            vollog.debug("Identified banner: {}".format(repr(banner)))

            symbol_files = linux_banners.get(banner, None)
            if symbol_files:
                isf_path = symbol_files[0]
                table_name = context.symbol_space.free_table_name('LintelStacker')
                table = linux.LinuxKernelIntermedSymbols(context,
                                                         'temporary.' + table_name,
                                                         name = table_name,
                                                         isf_url = isf_path)
                context.symbol_space.append(table)
                kaslr_shift, _ = LinuxUtilities.find_aslr(context,
                                                          table_name,
                                                          layer_name,
                                                          progress_callback = progress_callback)

                layer_class = intel.Intel  # type: Type
                if 'init_top_pgt' in table.symbols:
                    layer_class = intel.Intel32e
                    dtb_symbol_name = 'init_top_pgt'
                elif 'init_level4_pgt' in table.symbols:
                    layer_class = intel.Intel32e
                    dtb_symbol_name = 'init_level4_pgt'
                else:
                    dtb_symbol_name = 'swapper_pg_dir'

                dtb = LinuxUtilities.virtual_to_physical_address(
                    table.get_symbol(dtb_symbol_name).address + kaslr_shift)

                # Build the new layer
                new_layer_name = context.layers.free_layer_name("IntelLayer")
                config_path = join("IntelHelper", new_layer_name)
                context.config[join(config_path, "memory_layer")] = layer_name
                context.config[join(config_path, "page_map_offset")] = dtb
                context.config[join(config_path, LinuxSymbolFinder.banner_config_key)] = str(banner, 'latin-1')

                layer = layer_class(context, config_path = config_path, name = new_layer_name)

            if layer and dtb:
                vollog.debug("DTB was found at: 0x{:0x}".format(dtb))
                return layer
        return None


class LinuxUtilities(object):
    """Class with multiple useful linux functions."""

    # based on __d_path from the Linux kernel
    @classmethod
    def _do_get_path(cls, rdentry, rmnt, dentry, vfsmnt) -> str:

        ret_path = []  # type: List[str]

        while dentry != rdentry or vfsmnt != rmnt:
            dname = dentry.path()
            if dname == "":
                break

            ret_path.insert(0, dname.strip('/'))
            if dentry == vfsmnt.get_mnt_root() or dentry == dentry.d_parent:
                if vfsmnt.get_mnt_parent() == vfsmnt:
                    break

                dentry = vfsmnt.get_mnt_mountpoint()
                vfsmnt = vfsmnt.get_mnt_parent()

                continue

            parent = dentry.d_parent
            dentry = parent

        # if we did not gather any valid dentrys in the path, then the entire file is
        # either 1) smeared out of memory or 2) de-allocated and corresponding structures overwritten
        # we return an empty string in this case to avoid confusion with something like a handle to the root
        # directory (e.g., "/")
        if not ret_path:
            return ""

        ret_val = '/'.join([str(p) for p in ret_path if p != ""])

        if ret_val.startswith(("socket:", "pipe:")):
            if ret_val.find("]") == -1:
                try:
                    inode = dentry.d_inode
                    ino = inode.i_ino
                except exceptions.InvalidAddressException:
                    ino = 0

                ret_val = ret_val[:-1] + ":[{0}]".format(ino)
            else:
                ret_val = ret_val.replace("/", "")

        elif ret_val != "inotify":
            ret_val = '/' + ret_val

        return ret_val

    # method used by 'older' kernels
    # TODO: lookup when dentry_operations->d_name was merged into the mainline kernel for exact version
    @classmethod
    def _get_path_file(cls, task, filp) -> str:
        rdentry = task.fs.get_root_dentry()
        rmnt = task.fs.get_root_mnt()
        dentry = filp.get_dentry()
        vfsmnt = filp.get_vfsmnt()

        return LinuxUtilities._do_get_path(rdentry, rmnt, dentry, vfsmnt)

    @classmethod
    def _get_new_sock_pipe_path(cls, context, task, filp) -> str:
        dentry = filp.get_dentry()

        sym_addr = dentry.d_op.d_dname

        symbs = list(context.symbol_space.get_symbols_by_location(sym_addr))

        if len(symbs) == 1:
            sym = symbs[0].split(constants.BANG)[1]

            if sym == "sockfs_dname":
                pre_name = "socket"

            elif sym == "anon_inodefs_dname":
                pre_name = "anon_inode"

            elif sym == "pipefs_dname":
                pre_name = "pipe"

            elif sym == "simple_dname":
                pre_name = cls._get_path_file(task, filp)

            else:
                pre_name = "<unsupported d_op symbol: {0}>".format(sym)

            ret = "{0}:[{1:d}]".format(pre_name, dentry.d_inode.i_ino)

        else:
            ret = "<invalid d_dname pointer> {0:x}".format(sym_addr)

        return ret

    # a 'file' structure doesn't have enough information to properly restore its full path
    # we need the root mount information from task_struct to determine this
    @classmethod
    def path_for_file(cls, context, task, filp) -> str:
        try:
            dentry = filp.get_dentry()
        except exceptions.InvalidAddressException:
            return ""

        if dentry == 0:
            return ""

        dname_is_valid = False

        # TODO COMPARE THIS IN LSOF OUTPUT TO VOL2
        try:
            if dentry.d_op and dentry.d_op.has_member("d_dname") and dentry.d_op.d_dname:
                dname_is_valid = True

        except exceptions.InvalidAddressException:
            dname_is_valid = False

        if dname_is_valid:
            ret = LinuxUtilities._get_new_sock_pipe_path(context, task, filp)
        else:
            ret = LinuxUtilities._get_path_file(task, filp)

        return ret

    @classmethod
    def files_descriptors_for_process(cls, context: interfaces.context.ContextInterface, symbol_table: str,
                                      task: interfaces.objects.ObjectInterface):

        fd_table = task.files.get_fds()
        if fd_table == 0:
            return

        max_fds = task.files.get_max_fds()

        # corruption check
        if max_fds > 500000:
            return

        file_type = symbol_table + constants.BANG + 'file'

        fds = objects.utility.array_of_pointers(fd_table, count = max_fds, subtype = file_type, context = context)

        for (fd_num, filp) in enumerate(fds):
            if filp != 0:
                full_path = LinuxUtilities.path_for_file(context, task, filp)

                yield fd_num, filp, full_path

    @classmethod
    def aslr_mask_symbol_table(cls,
                               context: interfaces.context.ContextInterface,
                               symbol_table: str,
                               layer_name: str,
                               aslr_shift = 0) -> str:

        sym_layer = context.layers[layer_name]

        if aslr_shift == 0:
            if not isinstance(sym_layer, layers.intel.Intel):
                raise TypeError("Layer name {} is not an intel space")
            aslr_layer = sym_layer.config['memory_layer']
            _, aslr_shift = cls.find_aslr(context, symbol_table, aslr_layer)

        return symbols.mask_symbol_table(context, symbol_table, sym_layer.address_mask, aslr_shift)

    @classmethod
    def find_aslr(cls,
                  context: interfaces.context.ContextInterface,
                  symbol_table: str,
                  layer_name: str,
                  progress_callback: constants.ProgressCallback = None) \
            -> Tuple[int, int]:
        """Determines the offset of the actual DTB in physical space and its
        symbol offset."""
        init_task_symbol = symbol_table + constants.BANG + 'init_task'
        init_task_json_address = context.symbol_space.get_symbol(init_task_symbol).address
        swapper_signature = rb"swapper(\/0|\x00\x00)\x00\x00\x00\x00\x00\x00"
        module = context.module(symbol_table, layer_name, 0)

        for offset in context.layers[layer_name].scan(scanner = scanners.RegExScanner(swapper_signature),
                                                      context = context,
                                                      progress_callback = progress_callback):
            task_symbol = module.get_type('task_struct')
            init_task_address = offset - task_symbol.relative_child_offset('comm')
            init_task = module.object(object_type = 'task_struct', offset = init_task_address, absolute = True)
            if init_task.pid != 0:
                continue
            elif init_task.has_member('state') and init_task.state.cast('unsigned int') != 0:
                continue

            # This we get for free
            aslr_shift = init_task.files.cast('long unsigned int') - module.get_symbol('init_files').address
            kaslr_shift = init_task_address - cls.virtual_to_physical_address(init_task_json_address)

            if aslr_shift & 0xfff != 0 or kaslr_shift & 0xfff != 0:
                continue
            vollog.debug("Linux ASLR shift values determined: physical {:0x} virtual {:0x}".format(
                kaslr_shift, aslr_shift))
            return kaslr_shift, aslr_shift

        # We don't throw an exception, because we may legitimately not have an ASLR shift, but we report it
        vollog.debug("Scanners could not determine any ASLR shifts, using 0 for both")
        return 0, 0

    @classmethod
    def virtual_to_physical_address(cls, addr: int) -> int:
        """Converts a virtual linux address to a physical one (does not account
        of ASLR)"""
        if addr > 0xffffffff80000000:
            return addr - 0xffffffff80000000
        return addr - 0xc0000000
