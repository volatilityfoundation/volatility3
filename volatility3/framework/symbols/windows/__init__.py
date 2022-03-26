# This file is Copyright 2020 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

from volatility3.framework.symbols import intermed
from volatility3.framework.symbols.windows import extensions
from volatility3.framework.symbols.windows.extensions import registry, pool


class WindowsKernelIntermedSymbols(intermed.IntermediateSymbolTable):

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)

        # Set-up windows specific types
        self.set_type_class('_ETHREAD', extensions.ETHREAD)
        self.set_type_class('_KTHREAD', extensions.KTHREAD)
        self.set_type_class('_LIST_ENTRY', extensions.LIST_ENTRY)
        self.set_type_class('_EPROCESS', extensions.EPROCESS)
        self.set_type_class('_UNICODE_STRING', extensions.UNICODE_STRING)
        self.set_type_class('_EX_FAST_REF', extensions.EX_FAST_REF)
        self.set_type_class('_TOKEN', extensions.TOKEN)
        self.set_type_class('_OBJECT_HEADER', pool.OBJECT_HEADER)
        self.set_type_class('_FILE_OBJECT', extensions.FILE_OBJECT)
        self.set_type_class('_DEVICE_OBJECT', extensions.DEVICE_OBJECT)
        self.set_type_class('_CM_KEY_BODY', registry.CM_KEY_BODY)
        self.set_type_class('_CMHIVE', registry.CMHIVE)
        self.set_type_class('_CM_KEY_NODE', registry.CM_KEY_NODE)
        self.set_type_class('_CM_KEY_VALUE', registry.CM_KEY_VALUE)
        self.set_type_class('_HMAP_ENTRY', registry.HMAP_ENTRY)
        self.set_type_class('_MMVAD_SHORT', extensions.MMVAD_SHORT)
        self.set_type_class('_MMVAD', extensions.MMVAD)
        self.set_type_class('_KSYSTEM_TIME', extensions.KSYSTEM_TIME)
        self.set_type_class('_KMUTANT', extensions.KMUTANT)
        self.set_type_class('_DRIVER_OBJECT', extensions.DRIVER_OBJECT)
        self.set_type_class('_OBJECT_SYMBOLIC_LINK', extensions.OBJECT_SYMBOLIC_LINK)
        self.set_type_class('_CONTROL_AREA', extensions.CONTROL_AREA)
        self.set_type_class('_SHARED_CACHE_MAP', extensions.SHARED_CACHE_MAP)
        self.set_type_class('_VACB', extensions.VACB)
        self.set_type_class('_POOL_TRACKER_BIG_PAGES', pool.POOL_TRACKER_BIG_PAGES)

        # This doesn't exist in very specific versions of windows
        try:
            if self.get_type("_POOL_TRACKER_BIG_PAGES").has_member("PoolType"):
                self.set_type_class('_POOL_HEADER', pool.POOL_HEADER_VISTA)
            else:
                self.set_type_class('_POOL_HEADER', pool.POOL_HEADER)
        except ValueError:
            pass

        # these don't exist in windows XP
        try:
            self.set_type_class('_MMADDRESS_NODE', extensions.MMVAD_SHORT)
        except ValueError:
            pass

        # these were introduced starting in windows 8
        try:
            self.set_type_class('_MM_AVL_NODE', extensions.MMVAD_SHORT)
        except ValueError:
            pass

        # these were introduced starting in windows 7
        try:
            self.set_type_class('_RTL_BALANCED_NODE', extensions.MMVAD_SHORT)
        except ValueError:
            pass
