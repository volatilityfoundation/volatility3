'''
Created on 1 Dec 2012

@author: mike
'''

class VolatilityException(Exception):
    """Class to allow filtering of all VolatilityExceptions"""

class SymbolNotFoundException(VolatilityException):
    """Thrown when a symbol lookup has failed"""

class InvalidAddressException(VolatilityException):
    """Thrown when an address is not valid in the space it was requested"""

class SymbolSpaceError(VolatilityException):
    """Thrown when an error occurs dealing with Symbols and Symbolspaces"""
