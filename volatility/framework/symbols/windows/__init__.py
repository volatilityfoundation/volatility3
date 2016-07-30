from volatility.framework.configuration import requirements
from volatility.framework.symbols import vtypes
from volatility.framework.symbols.windows import extensions

__author__ = 'mike'


class WindowsKernelVTypeSymbols(vtypes.VTypeSymbolTable):
    provides = {"type": "interface"}

    def __init__(self, context, config_path, name, vtype_pymodule, vtype_variable):
        # FIXME: Make natives another requirement, or in some way hand it in when building the vtype_table
        vtypes.VTypeSymbolTable.__init__(self, name, vtype_pymodule, vtype_variable, context.symbol_space.natives)

        # Set-up windows specific types
        self.set_type_class('_ETHREAD', extensions._ETHREAD)
        self.set_type_class('_LIST_ENTRY', extensions._LIST_ENTRY)

    @classmethod
    def get_requirements(cls):
        return [requirements.StringRequirement("vtype_pymodule", description = "Python module containing the vtypes"),
                requirements.StringRequirement("vtype_variable",
                                               description = "Python vtypes variable within the module")]
