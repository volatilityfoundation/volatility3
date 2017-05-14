from volatility.framework.configuration import requirements
from volatility.framework.symbols import intermed
from volatility.framework.symbols.windows import extensions


class WindowsKernelIntermedSymbols(intermed.IntermediateSymbolTable):
    provides = {"type": "interface"}

    def __init__(self, context, config_path, name, isf_filepath):
        super().__init__(context = context, config_path = config_path, name = name, isf_filepath = isf_filepath)

        # Set-up windows specific types
        self.set_type_class('_ETHREAD', extensions._ETHREAD)
        self.set_type_class('_LIST_ENTRY', extensions._LIST_ENTRY)
        self.set_type_class('_EPROCESS', extensions._EPROCESS)
        self.set_type_class('_UNICODE_STRING', extensions._UNICODE_STRING)

    @classmethod
    def get_requirements(cls):
        return [requirements.StringRequirement("isf_filepath",
                                               description = "JSON file containing the symbols encoded in the Intermediate Symbol Format")]
