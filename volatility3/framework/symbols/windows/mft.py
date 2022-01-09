# This file is Copyright 2022 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

from volatility3.framework.symbols import intermed
from volatility3.framework.symbols.windows.extensions import mft


class MFTIntermedSymbols(intermed.IntermediateSymbolTable):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.set_type_class('FILE_NAME_ENTRY', mft.MFTFileName)
        self.set_type_class('MFT_ENTRY', mft.MFTEntry)
