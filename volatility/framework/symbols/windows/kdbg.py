from volatility.framework.symbols import intermed
from volatility.framework.symbols.windows.extensions import kdbg


class KdbgIntermedSymbols(intermed.IntermediateSymbolTable):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.set_type_class('_KDDEBUGGER_DATA64', kdbg._KDDEBUGGER_DATA64)
