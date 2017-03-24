from volatility.framework import constants
from volatility.framework import interfaces


def object_factory(context, symbol_table):
    """Allow a specific symbol_table to be used repeatedly for constructing objects

    :param symbol_table: The name of the symbol table that the object factory will construct objects on
    :type sybmol_table: str
    :return: A function that takes the same arguments as :func:`object`
    """

    def callable(symbol, layer_name, offset, **arguments):
        """Function to apply a specific symbol_table name to any unadorned symbol creation"""
        if constants.BANG not in symbol:
            symbol = symbol_table + constants.BANG + symbol
        return context.object(symbol, layer_name, offset, **arguments)

    return callable


def get_symbol_rebase(symbol_space, offset, symbol_table = None):
    """Construct a get_symbol function based on a symbol_space to return symbols whose addresses are all
     increased by a specific offset.

    :param symbol_space: The symbol_space object to use for symbol lookups
    :type symbol_space: str
    :param offset: The amount by which all symbol addresses are to be adjusted
    :param offset: int
    :param symbol_table: The (optional) name of the symbol table that get_symbol will search when no table name is provided as part of the symbol
    :type sybmol_table: str
    :return: A function that takes the same arguments as :func:`object`
    """
    if not (symbol_table is None or isinstance(symbol_table, str)):
        raise ValueError("symbol_table must be None or a string")

    def callable(symbol_name):
        """Function to apply a specific offset increase to returned symbols"""
        if constants.BANG not in symbol_name and symbol_table:
            symbol_name = symbol_table + constants.BANG + symbol_name
        symbol = symbol_space.get_symbol(symbol_name)
        new_symbol = interfaces.symbols.Symbol(name = symbol.name,
                                               address = symbol.address + offset,
                                               type = symbol.type)
        return new_symbol

    return callable
