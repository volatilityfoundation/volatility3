import typing

from volatility.framework import interfaces
from volatility.framework.configuration import requirements
from volatility.framework.symbols import intermed
from volatility.framework.symbols.mac import extensions

class MacKernelIntermedSymbols(intermed.IntermediateSymbolTable):
    provides = {"type": "interface"}

    def __init__(self,
                 context: interfaces.context.ContextInterface,
                 config_path: str,
                 name: str,
                 isf_url: str) -> None:
        super().__init__(context = context, config_path = config_path, name = name, isf_url = isf_url)

        self.set_type_class('proc',     extensions.proc)
        #self.set_type_class('fileglob', extensions.fileglob)
        #self.set_type_class('vnode',    extensions.vnode)

    @classmethod
    def get_requirements(cls) -> typing.List[interfaces.configuration.RequirementInterface]:
        return [requirements.StringRequirement("isf_url",
                                               description = "JSON file containing the symbols encoded in the Intermediate Symbol Format")]
