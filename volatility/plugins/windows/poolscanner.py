import enum
import typing

from volatility.framework import interfaces, validity, objects, renderers
from volatility.framework.configuration import requirements
from volatility.framework.interfaces import plugins
from volatility.framework.layers import scanners
from volatility.framework.renderers import format_hints


class PoolType(enum.IntEnum):
    """Class to maintain the different possible PoolTypes
    The values must be integer powers of 2

    FIXME: This can be removed and replaced with enum.IntFlag after python3.5 is deprecated
    """

    PAGED = 1
    NONPAGED = 2
    FREE = 4


class PoolConstraint(validity.ValidityRoutines):
    """Class to maintain tag/size/index/type information about Pool header tags"""

    def __init__(self,
                 tag: bytes,
                 page_type: typing.Optional[PoolType] = None,
                 size: typing.Optional[typing.Tuple[typing.Optional[int], typing.Optional[int]]] = None,
                 index: typing.Optional[typing.Tuple[typing.Optional[int], typing.Optional[int]]] = None,
                 alignment: typing.Optional[int] = 1):
        self.tag = self._check_type(tag, bytes)
        self.page_type = page_type
        self.size = size
        self.index = index
        self.alignment = alignment


class PoolScanner(plugins.PluginInterface):
    """Lists the processes present in a particular windows memory image"""

    @classmethod
    def get_requirements(cls):
        return [requirements.TranslationLayerRequirement(name = 'primary',
                                                         description = 'Kernel Address Space',
                                                         architectures = ["Intel32", "Intel64"]),
                requirements.SymbolRequirement(name = "nt_symbols", description = "Windows OS")]

    def _generator(self):
        constraints = [
            PoolConstraint(b'AtmT',
                           size = (200, None),
                           page_type = PoolType.PAGED | PoolType.NONPAGED | PoolType.FREE)
        ]
        base_layer = self.context.memory[self.config['primary']].config['memory_layer']
        for header in self.pool_scan(self._context,
                                     base_layer,
                                     self.config['nt_symbols'],
                                     constraints,
                                     alignment = 4):
            print(repr(header))

    @classmethod
    def pool_scan(cls,
                  context: interfaces.context.ContextInterface,
                  layer_name: str,
                  symbol_table: str,
                  pool_constraints: typing.List[PoolConstraint],
                  alignment: int = 4) -> typing.Generator[objects.Struct, None, None]:
        """Returns the _POOL_HEADER object (based on the symbol_table template) after scanning through layer_name
        returning all headers that match any of the constraints provided.  Only one constraint can be provided per tag"""
        # Setup the pattern
        constraint_lookup = {}
        for constraint in pool_constraints:
            constraint_lookup[constraint.tag] = constraint
        # Setup the pool header and offset differential
        module = context.module(symbol_table, layer_name)
        header_type = module.get_type('_POOL_HEADER')
        header_offset = header_type.relative_child_offset('PoolTag')

        # Run the scan locating the offsets of a particular tag
        layer = context.memory[layer_name]
        scanner = scanners.MultiStringScanner([c for c in constraint_lookup.keys()])
        for offset, pattern in layer.scan(context, scanner):
            test = constraint_lookup[pattern]
            header = module.object(type_name = "_POOL_HEADER", offset = offset - header_offset)

            # Size check
            if test.size is not None:
                if test.size[0]:
                    if (alignment * header.BlockSize) < test.size[0]:
                        continue
                if test.size[1]:
                    if (alignment * header.BlockSize) > test.size[1]:
                        continue

            # Type check
            if test.page_type is not None:
                if (test.page_type & PoolType.FREE):
                    if header.PoolType != 0:
                        continue
                if (test.page_type & PoolType.PAGED):
                    if header.PoolType % 2 == 0:
                        continue
                if (test.page_type & PoolType.NONPAGED):
                    if header.PoolType % 2 == 1 or header.PoolType < 0:
                        continue

            if test.index is not None:
                if test.index[0]:
                    if header.index < test.index[0]:
                        continue
                if test.size[1]:
                    if header.index > test.index[1]:
                        continue

            # We found one that passed!
            yield header

    def run(self) -> renderers.TreeGrid:
        return renderers.TreeGrid([("Tag", format_hints.Hex),
                                   ("Offset", format_hints.Hex),
                                   ("Layer", str),
                                   ("Name", str),
                                   ("Path", str)],
                                  self._generator())
