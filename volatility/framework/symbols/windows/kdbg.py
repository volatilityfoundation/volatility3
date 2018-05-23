import typing

from volatility.framework import interfaces
from volatility.framework.configuration import requirements
from volatility.framework.symbols import intermed
from volatility.framework.symbols.windows.extensions import kdbg

class KdbgIntermedSymbols(intermed.IntermediateSymbolTable):

    def __init__(self,
                 context: interfaces.context.ContextInterface,
                 config_path: str,
                 name: str,
                 isf_url: str) -> None:
        super().__init__(context = context, config_path = config_path, name = name, isf_url = isf_url)

        self.set_type_class('_KDDEBUGGER_DATA64', kdbg._KDDEBUGGER_DATA64)

    @classmethod
    def get_requirements(cls) -> typing.List[interfaces.configuration.RequirementInterface]:
        return [requirements.StringRequirement("isf_url",
                                               description="JSON file containing the symbols encoded in the Intermediate Symbol Format")]