import typing

from volatility.framework import interfaces, constants


def mask_symbol_table(symbol_table: interfaces.symbols.SymbolTableInterface,
                      address_mask: int = 0,
                      table_aslr_shift: int = 0):
    """Alters a symbol table, such that all symbols returned have their address masked by the address mask"""
    original_get_symbol = symbol_table.get_symbol
    cached_symbols = {}  # type: typing.Dict[interfaces.symbols.SymbolInterface, interfaces.symbols.SymbolInterface]

    def address_masked_get_symbol(*args, **kwargs):
        symbol = original_get_symbol(*args, **kwargs)
        # This is speedy, but may not be very efficient from a memory perspective
        if symbol in cached_symbols:
            return cached_symbols[symbol]
        new_symbol = interfaces.symbols.SymbolInterface(name = symbol.name,
                                                        address = address_mask & (symbol.address + table_aslr_shift),
                                                        type = symbol.type,
                                                        constant_data = symbol.constant_data)
        cached_symbols[symbol] = new_symbol
        return new_symbol

    original_get_symbol = symbol_table.get_symbol
    symbol_table.get_symbol = address_masked_get_symbol
    return symbol_table


def symbol_table_is_64bit(context: interfaces.context.ContextInterface,
                          symbol_table_name: str) -> bool:
    """Returns a boolean as to whether a particular symbol table within a context is 64-bit or not"""
    return context.symbol_space.get_type(symbol_table_name + constants.BANG + "pointer").size == 8
