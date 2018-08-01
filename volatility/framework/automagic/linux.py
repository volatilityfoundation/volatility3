import logging
import typing

from volatility.framework import constants, interfaces, validity
from volatility.framework.automagic import linux_symbol_cache
from volatility.framework.configuration import requirements
from volatility.framework.layers import intel, scanners
from volatility.framework.symbols import linux
from volatility.framework.symbols import utility as symbols_utility 
from volatility.framework.objects import utility

vollog = logging.getLogger(__name__)


class LinuxSymbolFinder(interfaces.automagic.AutomagicInterface):
    """Linux symbol loader based on uname signature strings"""
    priority = 40

    def __init__(self,
                 context: interfaces.context.ContextInterface,
                 config_path: str) -> None:
        super().__init__(context, config_path)
        self._requirements = []  # type: typing.List[typing.Tuple[str, interfaces.configuration.ConstructableRequirementInterface]]
        self._linux_banners_ = {}  # type: linux_symbol_cache.LinuxBanners

    @property
    def _linux_banners(self) -> linux_symbol_cache.LinuxBanners:
        """Creates a cached copy of the results, but only it's been requested"""
        if not self._linux_banners_:
            self._linux_banners_ = linux_symbol_cache.LinuxSymbolCache.load_linux_banners()
        return self._linux_banners_

    def __call__(self,
                 context: interfaces.context.ContextInterface,
                 config_path: str,
                 requirement: interfaces.configuration.RequirementInterface,
                 progress_callback: validity.ProgressCallback = None) -> None:
        """Searches for LinuxSymbolRequirements and attempt to populate them"""
        self._requirements = self.find_requirements(context, config_path, requirement,
                                                    (requirements.TranslationLayerRequirement,
                                                     requirements.SymbolRequirement),
                                                    shortcut = False)

        for (sub_path, requirement) in self._requirements:
            parent_path = interfaces.configuration.parent_path(sub_path)

            if (isinstance(requirement, requirements.SymbolRequirement) and requirement.unsatisfied(context,
                                                                                                    parent_path)):
                for (tl_sub_path, tl_requirement) in self._requirements:
                    tl_parent_path = interfaces.configuration.parent_path(tl_sub_path)
                    # Find the TranslationLayer sibling to the SymbolRequirement
                    if (isinstance(tl_requirement, requirements.TranslationLayerRequirement) and
                            tl_parent_path == parent_path):
                        if context.config.get(tl_sub_path, None):
                            self._banner_scan(context, parent_path, requirement, context.config[tl_sub_path],
                                              progress_callback)
                            break

    def _banner_scan(self,
                     context: interfaces.context.ContextInterface,
                     config_path: str,
                     requirement: interfaces.configuration.ConstructableRequirementInterface,
                     layer_name: str,
                     progress_callback: validity.ProgressCallback = None) -> None:
        """Accepts a context, config_path and SymbolRequirement, with a constructed layer_name
        and scans the layer for linux banners"""

        # Bomb out early if there's no banners
        if not self._linux_banners:
            return

        mss = scanners.MultiStringScanner([x for x in self._linux_banners if x is not None])

        layer = context.memory[layer_name]

        # Check if the Stacker has already found what we're looking for
        if layer.config.get('linux_banner', None):
            banner_list = [(0, bytes(layer.config['linux_banner'], 'latin-1'))]  # type: typing.Iterable[typing.Any]
        else:
            # Swap to the physical layer for scanning
            # TODO: Fix this so it works for layers other than just Intel
            layer = context.memory[layer.config['memory_layer']]
            banner_list = layer.scan(context = context, scanner = mss, progress_callback = progress_callback)

        for _, banner in banner_list:
            vollog.debug("Identified banner: {}".format(repr(banner)))
            symbol_files = self._linux_banners.get(banner, None)
            if symbol_files:
                isf_path = symbol_files[0]
                vollog.debug("Using symbol library: {}".format(symbol_files[0]))
                clazz = "volatility.framework.symbols.linux.LinuxKernelIntermedSymbols"
                # Set the discovered options
                path_join = interfaces.configuration.path_join
                context.config[path_join(config_path, requirement.name, "class")] = clazz
                context.config[path_join(config_path, requirement.name, "isf_url")] = isf_path
                # Construct the appropriate symbol table
                requirement.construct(context, config_path)
                break
            else:
                if symbol_files:
                    vollog.debug("Symbol library path not found: {}".format(symbol_files[0]))
                    # print("Kernel", banner, hex(banner_offset))
        else:
            vollog.debug("No existing linux banners found")
            # TODO: Fallback to generic regex search?


class LintelStacker(interfaces.automagic.StackerLayerInterface):
    stack_order = 12

    @classmethod
    def stack(cls,
              context: interfaces.context.ContextInterface,
              layer_name: str,
              progress_callback: validity.ProgressCallback = None) \
            -> typing.Optional[interfaces.layers.DataLayerInterface]:
        """Attempts to identify linux within this layer"""
        # Bail out by default unless we can stack properly
        layer = context.memory[layer_name]
        join = interfaces.configuration.path_join

        # Never stack on top of an intel layer
        # FIXME: Find a way to improve this check
        if isinstance(layer, intel.Intel):
            return None

        linux_banners = linux_symbol_cache.LinuxSymbolCache.load_linux_banners()
        mss = scanners.MultiStringScanner([x for x in linux_banners if x is not None])
        for _, banner in layer.scan(context = context, scanner = mss, progress_callback = progress_callback):
            dtb = None
            vollog.debug("Identified banner: {}".format(repr(banner)))

            symbol_files = linux_banners.get(banner, None)
            if symbol_files:
                isf_path = symbol_files[0]
                table_name = context.symbol_space.free_table_name('LintelStacker')
                table = linux.LinuxKernelIntermedSymbols(context, 'temporary.' + table_name, name = table_name,
                                                         isf_url = isf_path)
                context.symbol_space.append(table)
                kaslr_shift, _ = LinuxUtilities.find_aslr(context, table_name, layer_name,
                                                          progress_callback = progress_callback)

                layer_class = intel.Intel  # type: typing.Type
                if ('init_level4_pgt' in table.symbols):
                    layer_class = intel.Intel32e
                    dtb_symbol_name = 'init_level4_pgt'
                else:
                    dtb_symbol_name = 'swapper_pg_dir'

                dtb = LinuxUtilities.virtual_to_physical_address(table.get_symbol(dtb_symbol_name).address +
                                                                 kaslr_shift)

                # Build the new layer
                new_layer_name = context.memory.free_layer_name("IntelLayer")
                config_path = join("IntelHelper", new_layer_name)
                context.config[join(config_path, "memory_layer")] = layer_name
                context.config[join(config_path, "page_map_offset")] = dtb
                context.config[join(config_path, "linux_banner")] = str(banner, 'latin-1')

                layer = layer_class(context, config_path = config_path, name = new_layer_name)

            if layer and dtb:
                vollog.debug("DTB was found at: 0x{:0x}".format(dtb))
                return layer
        return None


class LinuxUtilities(object):
    """Class with multiple useful linux functions"""

    # based on __d_path from the Linux kernel
    @classmethod
    def _do_get_path(cls, rdentry, rmnt, dentry, vfsmnt) -> str:
        try:
            rdentry.validate()
            dentry.validate()
        except InvalidDataException:
            return ""

        ret_path = [] # type: typing.List[str]

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

        if ret_path == []:
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
        rmnt    = task.fs.get_root_mnt()
        dentry  = filp.get_dentry()
        vfsmnt  = filp.get_vfsmnt()
    
        return LinuxUtilities._do_get_path(rdentry, rmnt, dentry, vfsmnt)

    @classmethod
    def _get_new_sock_pipe_path(cls, task, filp) -> str:
        dentry = filp.get_dentry()

        sym_addr = dentry.d_op.d_dname

        # IKELOS: _contet.symbol_space has already been masked  (including ASLR) by the run() function of the calling plugin. This makes the code super clean
        symbols = list(dentry._context.symbol_space.get_symbols_by_location(sym_addr))
        
        if len(symbols) == 1:
            sym = symbols[0].split("!")[1]
            
            if sym == "sockfs_dname":
                pre_name = "socket"    
        
            elif sym == "anon_inodefs_dname":
                pre_name = "anon_inode"

            elif sym == "pipefs_dname":
                pre_name = "pipe"

            elif sym == "simple_dname":
                pre_name = self._get_path_file(filp)

            else:
                pre_name = "<unsupported d_op symbol: {0}>".format(sym)

            ret = "{0}:[{1:d}]".format(pre_name, dentry.d_inode.i_ino)

        else:
            ret = "<invalid d_dname pointer> {0:x}".format(sym_addr)

        return ret

    # a 'file' structure doesn't have enough information to properly restore its full path
    # we need the root mount information from task_struct to determine this
    @classmethod
    def path_for_file(cls, task, filp) -> str:
        try:
            dentry = filp.get_dentry()
        except exceptions.InvalidAddressException:
            return ""

        if dentry == 0:
            return ""

        dname_is_valid = False

        # TODO COMPARE THIS IN LSOF OUTPUT TO VOL2
        try:
            if dentry.d_op and hasattr(dentry.d_op, "d_dname") and dentry.d_op.d_dname:
                dname_is_valid = True

        except exceptions.InvalidAddressException:
            dname_is_valid = False

        if dname_is_valid:
            ret = LinuxUtilities._get_new_sock_pipe_path(task, filp)
        else:
            ret = LinuxUtilities._get_path_file(task, filp)

        return ret
   
    # IKELOS: 'task' will always be a task_struct as defined in the profile json. Do I type this in the parameter list? If so, how?
    # IKELOS: what should the type of 'config' be? 
    @classmethod
    def files_descriptors_for_process(cls,
                                      config,
                                      context: interfaces.context.ContextInterface,
                                      task):

        fd_table = task.files.get_fds()
        if fd_table == 0:
            return

        max_fds  = task.files.get_max_fds()
        
        # corruption check
        if max_fds > 500000:
            return

        file_type = config["vmlinux"] + constants.BANG + 'file'
        
        fds = utility.array_of_pointers(fd_table, count = max_fds, subtype = file_type, context = context)

        for (fd_num, filp) in enumerate(fds):
            if filp != 0:
                full_path = LinuxUtilities.path_for_file(task, filp)

                yield fd_num, filp, full_path

    @classmethod
    def aslr_mask_symbol_table(cls,
                               config, 
                               context: interfaces.context.ContextInterface):

        aslr_layer    = config['primary.memory_layer']
        _, aslr_shift = LinuxUtilities.find_aslr(context, config["vmlinux"], aslr_layer)

        sym_table_name = config["vmlinux"]
        sym_layer_name = config["primary"]
        symbols_utility.mask_symbol_table(context.symbol_space[sym_table_name], context.memory[sym_layer_name].address_mask, aslr_shift)

    @classmethod
    def find_aslr(cls,
                  context: interfaces.context.ContextInterface,
                  symbol_table: str,
                  layer_name: str,
                  progress_callback: validity.ProgressCallback = None) \
            -> typing.Tuple[int, int]:
        """Determines the offset of the actual DTB in physical space and its symbol offset"""
        init_task_symbol = symbol_table + constants.BANG + 'init_task'
        table_dtb = context.symbol_space.get_symbol(init_task_symbol).address
        swapper_signature = b"swapper/0\x00\x00\x00\x00\x00\x00"
        module = context.module(symbol_table, layer_name, 0)

        for offset in context.memory[layer_name].scan(scanner = scanners.RegExScanner(swapper_signature),
                                                      context = context, progress_callback = progress_callback):
            task_symbol = module.get_type('task_struct')
            image_dtb = offset - task_symbol.relative_child_offset('comm')
            init_task = module.object(type_name = 'task_struct', offset = image_dtb)
            if init_task.pid != 0:
                continue
            if init_task.has_member('thread_info') and init_task.thread_info.cast('unsigned int') != 0:
                continue
            elif (init_task.has_member('state') and init_task.state.cast('unsigned int') != 0):
                continue
            # This we get for free
            aslr_shift = init_task.files.cast('long long unsigned int') - module.get_symbol('init_files').address
            kaslr_shift = image_dtb - cls.virtual_to_physical_address(table_dtb)

            if aslr_shift & 0xfff != 0 or kaslr_shift & 0xfff != 0:
                continue
            vollog.debug(
                "Linux ASLR shift values determined: physical {:0x} virtual {:0x}".format(kaslr_shift, aslr_shift))
            return kaslr_shift, aslr_shift

        # We don't throw an exception, because we may legitimately not have an ASLR shift, but we report it
        vollog.debug("Scanners could not determine any ASLR shifts, using 0 for both")
        return 0, 0

    @classmethod
    def virtual_to_physical_address(cls, addr: int) -> int:
        """Converts a virtual linux address to a physical one (does not account of ASLR)"""
        if addr > 0xffffffff80000000:
            return addr - 0xffffffff80000000
        return addr - 0xc0000000
