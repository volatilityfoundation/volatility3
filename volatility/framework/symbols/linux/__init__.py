from volatility.framework import interfaces
from volatility.framework.symbols import intermed
from volatility.framework.symbols.linux import extensions


class LinuxKernelIntermedSymbols(intermed.IntermediateSymbolTable):
    provides = {"type": "interface"}

    def __init__(self, context: interfaces.context.ContextInterface, config_path: str, name: str,
                 isf_url: str) -> None:
        super().__init__(context = context, config_path = config_path, name = name, isf_url = isf_url)

        # Set-up Linux specific types
        self.set_type_class('file', extensions.struct_file)
        self.set_type_class('list_head', extensions.list_head)
        self.set_type_class('mm_struct', extensions.mm_struct)
        self.set_type_class('super_block', extensions.super_block)
        self.set_type_class('task_struct', extensions.task_struct)
        self.set_type_class('vm_area_struct', extensions.vm_area_struct)
        self.set_type_class('qstr', extensions.qstr)
        self.set_type_class('dentry', extensions.dentry)
        self.set_type_class('fs_struct', extensions.fs_struct)
        self.set_type_class('files_struct', extensions.files_struct)
        self.set_type_class('vfsmount', extensions.vfsmount)
        self.set_type_class('module', extensions.module)

        if 'mount' in self.types:
            self.set_type_class('mount', extensions.mount)
