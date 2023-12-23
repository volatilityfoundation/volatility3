# This file is Copyright 2022 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

from volatility3.framework.symbols import intermed
from volatility3.framework.symbols.linux.extensions import hash


class HashIntermedSymbols(intermed.IntermediateSymbolTable):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.set_type_class("bash_hash_table", hash.bash_hash_table)
