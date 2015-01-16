import volatility
from volatility.framework import layers
from volatility.framework.symbols import vtypes, native, windows

__author__ = 'mike'

from volatility.framework import interfaces


class ContextPhysicalLoaderInterface(interfaces.context.ContextFactoryInterface):
    def construct_physical_layers(self, context):
        # TODO: Add in the physical layer automagic to determine the layering
        # Ideally allow for the plugin to specify the layering, but if not then guess at the best one
        base = layers.physical.FileLayer(context, 'data', filename = '/home/mike/memory/private/jon-fres.dmp')
        context.add_layer(base)


### NATIVE TYPES

class Context32Bit(ContextPhysicalLoaderInterface):
    def construct_context(self):
        """Creates a base context with the 32-bit NativeTables"""
        native_list = native.x86NativeTable
        return volatility.framework.Context(native_list)


class Context64Bit(ContextPhysicalLoaderInterface):
    def construct_context(self):
        """Creates a base context with the 32-bit NativeTables"""
        native_list = native.x64NativeTable
        return volatility.framework.Context(native_list)


### INTEL SPACES

class ContextIntel(Context32Bit):
    def construct_architecture(self, context):
        # TODO: Determine the DTB
        intel = layers.intel.Intel(context, 'kernel', 'data', page_map_offset = 0x319000)
        context.add_layer(intel)


class ContextIntelPAE(Context32Bit):
    def construct_architecture(self, context):
        # TODO: Determine the DTB
        intel = layers.intel.IntelPAE(context, 'kernel', 'data', page_map_offset = 0x319000)
        context.add_layer(intel)


class ContextIntelX64(Context64Bit):
    def construct_architecture(self, context):
        # TODO; Determine the DTB
        intel = layers.intel.Intel32e(context, 'kernel', 'data', page_map_offset = 0x319000)
        context.add_layer(intel)


### Operating Systems

class ContextWindowsX86(ContextIntel):
    # TODO: Only import the vtypes during init
    def __init__(self):
        from volatility.framework import xp_sp2_x86_vtypes

        self._virtual_types = xp_sp2_x86_vtypes.ntkrnlmp_types

    def construct_os_symbols(self, context):
        virtual_types = self._virtual_types
        ntkrnlmp = vtypes.VTypeSymbolTable('ntkrnlmp', virtual_types, context.symbol_space.natives)
        ntkrnlmp.set_structure_class('_ETHREAD', windows._ETHREAD)
        ntkrnlmp.set_structure_class('_LIST_ENTRY', windows._LIST_ENTRY)
        context.symbol_space.append(ntkrnlmp)
