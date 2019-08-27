# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl_v1.0
#

from volatility.framework import interfaces
from volatility.framework.symbols import intermed
from volatility.framework.symbols.mac import extensions


class MacKernelIntermedSymbols(intermed.IntermediateSymbolTable):
    provides = {"type": "interface"}

    def __init__(self, context: interfaces.context.ContextInterface, config_path: str, name: str, isf_url: str) -> None:
        super().__init__(context = context, config_path = config_path, name = name, isf_url = isf_url)

        self.set_type_class('proc', extensions.proc)
        self.set_type_class('fileglob', extensions.fileglob)
        self.set_type_class('vnode', extensions.vnode)
        self.set_type_class('vm_map_entry', extensions.vm_map_entry)
        self.set_type_class('vm_map_object', extensions.vm_map_object)
        self.set_type_class('socket', extensions.socket)
        self.set_type_class('inpcb', extensions.inpcb)
        self.set_type_class('queue_entry', extensions.queue_entry)

