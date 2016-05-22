import importlib

from volatility.framework import interfaces
from volatility.framework.configuration import requirements
from volatility.framework.symbols import vtypes, native
from volatility.framework.symbols.windows import extensions


class X86NativeSymbolProvider(interfaces.symbols.SymbolTableProviderInterface):
    provides = {"type": "natives",
                "architecture": ["ia32", "pae"]}

    @classmethod
    def fulfill(cls, context, requirement, config_path):
        context.symbol_space.natives = native.x86NativeTable
        context.config[config_path] = "natives"


class WindowsKernelSymbolProvider(interfaces.symbols.SymbolTableProviderInterface):
    provides = {"type": "interface"}

    vtype_pymodule = ""
    vtype_variable = ""
    space_name = ""

    @classmethod
    def fulfill(cls, context, requirement, config_path):
        # Delay importing to reduce unnecessary memory and time wastage
        try:
            module = importlib.import_module("volatility.framework.symbols.windows." + cls.vtype_pymodule)
        except ImportError:
            raise TypeError("VType Provider interface cannot be used to fulfill a requirement")
        virtual_types = getattr(module, cls.vtype_variable)

        # Check the space_name isn't already in use
        if cls.space_name in context.symbol_space:
            raise KeyError("Symbol space " + cls.space_name + " already exists")
        vtype_table = vtypes.VTypeSymbolTable(cls.space_name, virtual_types, context.symbol_space.natives)

        # Set-up windows specific types
        vtype_table.set_type_class('_ETHREAD', extensions._ETHREAD)
        vtype_table.set_type_class('_LIST_ENTRY', extensions._LIST_ENTRY)

        context.symbol_space.append(vtype_table)
        context.config[config_path] = cls.space_name


class XPSP2WindowsKernelSymbolProvider(WindowsKernelSymbolProvider):
    provides = {"type": "symbols",
                "os": "windows",
                "major": 5,
                "minor": 1,
                "build": 1500,
                "architecture": ["ia32", "pae"],
                }

    vtype_pymodule = "xp_sp2_x86_vtypes"
    vtype_variable = "ntkrnlmp_types"
    space_name = 'ntkrnlmp'

    @classmethod
    def get_schema(cls):
        return [requirements.NativeSymbolRequirement("natives", description = "Native Symbols for x86",
                                                     constraints = {"type": "natives",
                                                                    "architecture": "ia32"})]
