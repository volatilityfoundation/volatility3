from volatility.framework.configuration import requirements
from volatility.framework.symbols import intermed
from volatility.framework.symbols.linux import extensions


class LinuxKernelIntermedSymbols(intermed.IntermediateSymbolTable):
    provides = {"type": "interface"}

    def __init__(self, context, config_path, name, isf_filepath):
        super().__init__(context = context, config_path = config_path, name = name, isf_filepath = isf_filepath)

        # Set-up Linux specific types
        self.set_type_class('file', extensions.struct_file)
        self.set_type_class('list_head', extensions.list_head)
        self.set_type_class('mm_struct', extensions.mm_struct)
        self.set_type_class('super_block', extensions.super_block)
        self.set_type_class('task_struct', extensions.task_struct)
        self.set_type_class('vm_area_struct', extensions.vm_area_struct)


    @classmethod
    def get_requirements(cls):
        return [requirements.StringRequirement("isf_filepath",
                                               description = "JSON file containing the symbols encoded in the Intermediate Symbol Format")]
