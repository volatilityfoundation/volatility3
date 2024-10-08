# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

from volatility3.framework import constants, interfaces, objects
from volatility3.framework.objects import utility
from volatility3.framework.symbols import intermed
from volatility3.framework.symbols.freebsd import extensions


class FreebsdKernelIntermedSymbols(intermed.IntermediateSymbolTable):
    provides = {"type": "interface"}

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)

        self.set_type_class("proc", extensions.proc)
        self.set_type_class("vm_map_entry", extensions.vm_map_entry)
        self.set_type_class("vnode", extensions.vnode)


class FreebsdUtilities(interfaces.configuration.VersionableInterface):
    """Class with multiple useful freebsd functions."""
    _version = (1, 0, 0)
    _required_framework_version = (2, 0, 0)

    @classmethod
    def files_descriptors_for_process(
        cls,
        context: interfaces.context.ContextInterface,
        kernel,
        task: interfaces.objects.ObjectInterface,
    ):
        """Creates a generator for the file descriptors of a process

        Args:
            kernel:
            context:
            task: The process structure to enumerate file descriptors from

        Return:
            A 3 element tuple is yielded for each file descriptor:
            1) The file's object
            2) The path referenced by the descriptor.
                The path is either empty, the full path of the file in the file system, or the formatted name for sockets, pipes, etc.
            3) The file descriptor number
        """
        num_fds = task.p_fd.fd_files.fdt_nfiles
        table_addr = task.p_fd.fd_files.fdt_ofiles.vol.offset

        fds = kernel.object(
            object_type = "array",
            offset = table_addr,
            count = num_fds,
            subtype = kernel.get_type("filedescent"),
        )

        for fd_num, f in enumerate(fds):
            if f.fde_file and f.fde_file.f_type:
                if f.fde_file.f_type == 1:  # DTYPE_VNODE
                    vnode = f.fde_file.f_vnode
                    # XXX there seems to be a bug in enumerations, we can't get vnode.v_type..
                    path = vnode.get_vpath(kernel)
                    if not path and vnode.v_rdev:
                        path = utility.array_to_string(vnode.v_rdev.si_name)
                    if not path:
                        path = "-"
                elif f.fde_file.f_type == 2:  # DTYPE_SOCKET
                    socket = f.fde_file.f_data.dereference().cast("socket")
                    path = f"<SOCKET AF_{socket.so_proto.pr_domain.dom_family} IPPROTO_{socket.so_proto.pr_protocol}>"
                else:
                    path = f"<DTYPE_{f.fde_file.f_type}>"

                yield f.fde_file, path, fd_num
