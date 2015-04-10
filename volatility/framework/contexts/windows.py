from volatility.framework import interfaces
from volatility.framework.symbols import vtypes, windows

__author__ = 'mike'


class WindowsContextModifier(interfaces.context.ContextModifierInterface):
    # TODO: Only import the vtypes only when necessary
    def __init__(self, config):
        from volatility.framework import xp_sp2_x86_vtypes

        self._virtual_types = xp_sp2_x86_vtypes.ntkrnlmp_types

    @classmethod
    def requirements(cls):
        return []

    def __call__(self, context):
        virtual_types = self._virtual_types
        ntkrnlmp = vtypes.VTypeSymbolTable('ntkrnlmp', virtual_types, context.symbol_space.natives)
        ntkrnlmp.set_structure_class('_ETHREAD', windows._ETHREAD)
        ntkrnlmp.set_structure_class('_LIST_ENTRY', windows._LIST_ENTRY)
        context.symbol_space.append(ntkrnlmp)
