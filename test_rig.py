'''
Created on 10 Mar 2013

@author: mike
'''

from volatility.framework import xp_sp2_x86_vtypes, symbols

if __name__ == '__main__':
    vtypes = xp_sp2_x86_vtypes.ntkrnlmp_types

    ntkrnlmp = symbols.VTypeSymbolList('ntkrnlmp', vtypes)
    sspace = symbols.SymbolSpace()
    sspace.append(ntkrnlmp)
    for i in ntkrnlmp.symbols:
        print(sspace.resolve('ntkrnlmp!' + i))

