'''
Created on 10 Mar 2013

@author: mike
'''

import pdb
from volatility.framework import xp_sp2_x86_vtypes, context, symbols
from volatility.framework.symbols import vtypes, native

def main():
    nativelst = native.x86NativeTable

    virtual_types = xp_sp2_x86_vtypes.ntkrnlmp_types

    ntkrnlmp = vtypes.VTypeSymbolTable('ntkrnlmp', virtual_types, nativelst)

    ctx = context.Context(symbols.SymbolSpace(nativelst))
    ctx.symbol_space.append(nativelst)
    ctx.symbol_space.append(ntkrnlmp)
    print("Symbols,", nativelst.symbols)

    for _ in []: # 1, 2]:
        for i in list(ntkrnlmp.symbols):
            symbol = ctx.symbol_space.resolve('ntkrnlmp!' + i)
            print(symbol.symbol_name, symbol, symbol.size)
            # objthing = symbol(context, layer_name = '', offset = 0)
    symbol = ctx.symbol_space.resolve('ntkrnlmp!_EPROCESS')


if __name__ == '__main__':
    # import timeit
    # print(timeit.Timer(main).timeit(10))
    try:
        main()
    except Exception as e:
        print(repr(e))
        pdb.post_mortem()
