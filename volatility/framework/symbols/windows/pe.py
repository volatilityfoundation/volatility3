import typing

from volatility.framework import interfaces
from volatility.framework.configuration import requirements
from volatility.framework.symbols import intermed
from volatility.framework.symbols.windows.extensions import pe

class PEIntermedSymbols(intermed.IntermediateSymbolTable):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.set_type_class('_IMAGE_DOS_HEADER', pe._IMAGE_DOS_HEADER)
        # the 32- and 64-bit extensions behave the same way, but the underlying structure is different
        self.set_type_class('_IMAGE_NT_HEADERS', pe._IMAGE_NT_HEADERS)
        self.set_type_class('_IMAGE_NT_HEADERS64', pe._IMAGE_NT_HEADERS)

    @classmethod
    def get_requirements(cls) -> typing.List[interfaces.configuration.RequirementInterface]:
        return [requirements.StringRequirement("isf_url",
                                               description="JSON file containing the symbols encoded in the Intermediate Symbol Format")]