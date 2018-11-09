import enum
import logging
import typing

from volatility.framework import constants, interfaces, renderers, validity, exceptions, symbols
from volatility.framework.configuration import requirements
from volatility.framework.interfaces import plugins, configuration
from volatility.framework.layers import scanners
from volatility.framework.renderers import format_hints
from volatility.framework.symbols import intermed
from volatility.framework.symbols.windows import extensions
import volatility.plugins.windows.handles as handles

vollog = logging.getLogger(__name__)


class PoolType(enum.IntEnum):
    """Class to maintain the different possible PoolTypes
    The values must be integer powers of 2"""

    PAGED = 1
    NONPAGED = 2
    FREE = 4


class PoolHeaderSymbolTable(intermed.IntermediateSymbolTable):
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.set_type_class('_POOL_HEADER', extensions._POOL_HEADER)


class PoolConstraint(validity.ValidityRoutines):
    """Class to maintain tag/size/index/type information about Pool header tags"""

    def __init__(self,
                 tag: bytes,
                 type_name: str,
                 object_type: typing.Optional[str] = None,
                 page_type: typing.Optional[PoolType] = None,
                 size: typing.Optional[typing.Tuple[typing.Optional[int], typing.Optional[int]]] = None,
                 index: typing.Optional[typing.Tuple[typing.Optional[int], typing.Optional[int]]] = None,
                 alignment: typing.Optional[int] = 1) -> None:
        self.tag = self._check_type(tag, bytes)
        self.type_name = type_name
        self.object_type = object_type
        self.page_type = page_type
        self.size = size
        self.index = index
        self.alignment = alignment


class PoolScanner(plugins.PluginInterface):
    """A generic pool scanner plugin"""

    @classmethod
    def get_requirements(cls):
        return [requirements.TranslationLayerRequirement(name = 'primary',
                                                         description = 'Kernel Address Space',
                                                         architectures = ["Intel32", "Intel64"]),
                requirements.SymbolRequirement(name = "nt_symbols", description = "Windows OS")]

    def _generator(self):
        constraints = [
            # atom tables
            PoolConstraint(b'AtmT',
                           type_name = self.config["nt_symbols"] + constants.BANG + "_RTL_ATOM_TABLE",
                           size = (200, None),
                           page_type = PoolType.PAGED | PoolType.NONPAGED | PoolType.FREE),
            # processes on windows before windows 8
            PoolConstraint(b'Pro\xe3',
                           type_name = self.config["nt_symbols"] + constants.BANG + "_EPROCESS",
                           object_type = "Process",
                           size = (600, None),
                           page_type = PoolType.PAGED | PoolType.NONPAGED | PoolType.FREE),
            # processes on windows starting with windows 8
            PoolConstraint(b'Proc',
                           type_name = self.config["nt_symbols"] + constants.BANG + "_EPROCESS",
                           object_type = "Process",
                           size = (600, None),
                           page_type = PoolType.PAGED | PoolType.NONPAGED | PoolType.FREE),
            # files on windows before windows 8
            PoolConstraint(b'Fil\xe5',
                           type_name = self.config["nt_symbols"] + constants.BANG + "_FILE_OBJECT",
                           object_type = "File",
                           size = (150, None),
                           page_type = PoolType.PAGED | PoolType.NONPAGED | PoolType.FREE),
            # files on windows starting with windows 8
            PoolConstraint(b'File',
                           type_name = self.config["nt_symbols"] + constants.BANG + "_FILE_OBJECT",
                           object_type = "File",
                           size = (150, None),
                           page_type = PoolType.PAGED | PoolType.NONPAGED | PoolType.FREE),
        ]

        # get the object type map
        type_map = handles.Handles.list_objects(context = self.context,
                                                layer_name = self.config["primary"],
                                                symbol_table = self.config["nt_symbols"])

        cookie = handles.Handles.find_cookie(context = self.context,
                                             layer_name = self.config["primary"],
                                             symbol_table = self.config["nt_symbols"])

        # FIXME: replace these lambdas with real functions
        is_windows_10 = lambda: False
        is_windows_8_or_later = lambda: False

        # FIXME: scanning the primary layer seems very slow (10min on 512mb grrcon)
        # start off with the primary virtual layer
        scan_layer = self.config['primary']

        # switch to a non-virtual layer if necessary
        if not is_windows_10():
            scan_layer = self.context.memory[scan_layer].config['memory_layer']

        for constraint, header in self.pool_scan(self._context,
                                                 scan_layer,
                                                 self.config['nt_symbols'],
                                                 constraints,
                                                 alignment = 8):

            mem_object = header.get_object(type_name = constraint.type_name,
                                           type_map = type_map,
                                           use_top_down = is_windows_8_or_later(),
                                           object_type = constraint.object_type,
                                           native_layer_name = 'primary',
                                           cookie = cookie)

            if mem_object is None:
                vollog.log(constants.LOGLEVEL_VVV, "Cannot create an instance of {}".format(constraint.type_name))
                continue

            # generate some type-specific info for sanity checking
            if constraint.object_type == "Process":
                name = mem_object.ImageFileName.cast("string",
                                                     max_length = mem_object.ImageFileName.vol.count,
                                                     errors = "replace")
            elif constraint.object_type == "File":
                try:
                    name = mem_object.FileName.String
                except exceptions.PagedInvalidAddressException:
                    vollog.log(constants.LOGLEVEL_VVV, "Skipping file at {0:#x}".format(mem_object.vol.offset))
                    continue
            else:
                name = renderers.NotApplicableValue()

            yield (0, (constraint.type_name,
                       format_hints.Hex(header.vol.offset),
                       header.vol.layer_name,
                       name))

    @classmethod
    def pool_scan(cls,
                  context: interfaces.context.ContextInterface,
                  layer_name: str,
                  symbol_table: str,
                  pool_constraints: typing.List[PoolConstraint],
                  alignment: int = 8,
                  progress_callback: typing.Optional[validity.ProgressCallback] = None) \
            -> typing.Generator[typing.Tuple[PoolConstraint, interfaces.objects.ObjectInterface], None, None]:
        """Returns the _POOL_HEADER object (based on the symbol_table template) after scanning through layer_name
        returning all headers that match any of the constraints provided.  Only one constraint can be provided per tag"""
        # Setup the pattern
        constraint_lookup = {}  # type: typing.Dict[bytes, typing.List[PoolConstraint]]
        for constraint in pool_constraints:
            temp_list = constraint_lookup.get(constraint.tag, [])
            temp_list.append(constraint)
            constraint_lookup[constraint.tag] = temp_list
        # Setup the pool header and offset differential
        try:
            module = context.module(symbol_table, layer_name, offset = 0)
            header_type = module.get_type('_POOL_HEADER')
        except exceptions.SymbolError:
            # We have to manually load a symbol table

            if symbols.symbol_table_is_64bit(context, symbol_table):
                # FIXME: Do proper test for is_win_7
                is_win_7 = False
                if is_win_7:
                    pool_header_json_filename = "poolheader-x64-win7"
                else:
                    pool_header_json_filename = "poolheader-x64"
            else:
                pool_header_json_filename = "poolheader-x86"

            new_table_name = PoolHeaderSymbolTable.create(context = context,
                                                          config_path = configuration.path_join(
                                                              context.symbol_space[symbol_table].config_path,
                                                              "poolheader"
                                                          ),
                                                          sub_path = "windows",
                                                          filename = pool_header_json_filename,
                                                          table_mapping = {'nt_symbols': symbol_table})
            module = context.module(new_table_name, layer_name, offset = 0)
            header_type = module.get_type('_POOL_HEADER')

        header_offset = header_type.relative_child_offset('PoolTag')

        # Run the scan locating the offsets of a particular tag
        layer = context.memory[layer_name]
        scanner = scanners.MultiStringScanner([c for c in constraint_lookup.keys()])
        for offset, pattern in layer.scan(context, scanner, progress_callback = progress_callback):
            for constraint in constraint_lookup[pattern]:
                header = module.object(type_name = "_POOL_HEADER", offset = offset - header_offset)

                # Size check
                try:
                    if constraint.size is not None:
                        if constraint.size[0]:
                            if (alignment * header.BlockSize) < constraint.size[0]:
                                continue
                        if constraint.size[1]:
                            if (alignment * header.BlockSize) > constraint.size[1]:
                                continue

                    # Type check
                    if constraint.page_type is not None:
                        checks_pass = False

                        if (constraint.page_type & PoolType.FREE) and header.PoolType == 0:
                            checks_pass = True
                        elif (
                                constraint.page_type & PoolType.PAGED) and header.PoolType % 2 == 0 and header.PoolType > 0:
                            checks_pass = True
                        elif (constraint.page_type & PoolType.NONPAGED) and header.PoolType % 2 == 1:
                            checks_pass = True

                        if not checks_pass:
                            continue

                    if constraint.index is not None:
                        if constraint.index[0]:
                            if header.index < constraint.index[0]:
                                continue
                        if constraint.index[1]:
                            if header.index > constraint.index[1]:
                                continue
                except exceptions.InvalidAddressException:
                    # The tested object's header doesn't point to valid addresses, ignore it
                    continue

                # We found one that passed!
                yield (constraint, header)

    def run(self) -> renderers.TreeGrid:
        return renderers.TreeGrid([("Tag", str),
                                   ("Offset", format_hints.Hex),
                                   ("Layer", str),
                                   ("Name", str)],
                                  self._generator())
