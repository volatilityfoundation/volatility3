# This file was contributed to the Volatility Framework Version 3.
# Copyright (C) 2018 Volatility Foundation.
#
# THE LICENSED WORK IS PROVIDED UNDER THE TERMS OF THE Volatility Contributors
# Public License V1.0("LICENSE") AS FIRST COMPLETED BY: Volatility Foundation,
# Inc. ANY USE, PUBLIC DISPLAY, PUBLIC PERFORMANCE, REPRODUCTION OR DISTRIBUTION
# OF, OR PREPARATION OF SUBSEQUENT WORKS, DERIVATIVE WORKS OR DERIVED WORKS BASED
# ON, THE LICENSED WORK CONSTITUTES RECIPIENT'S ACCEPTANCE OF THIS LICENSE AND ITS
# TERMS, WHETHER OR NOT SUCH RECIPIENT READS THE TERMS OF THE LICENSE. "LICENSED
# WORK,” “RECIPIENT" AND “DISTRIBUTOR" ARE DEFINED IN THE LICENSE. A COPY OF THE
# LICENSE IS LOCATED IN THE TEXT FILE ENTITLED "LICENSE.txt" ACCOMPANYING THE
# CONTENTS OF THIS FILE. IF A COPY OF THE LICENSE DOES NOT ACCOMPANY THIS FILE, A
# COPY OF THE LICENSE MAY ALSO BE OBTAINED AT THE FOLLOWING WEB SITE:
# https://www.volatilityfoundation.org/license/vcpl_v1.0
#
# Software distributed under the License is distributed on an "AS IS" basis,
# WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License for the
# specific language governing rights and limitations under the License.
#

import enum
import logging
from typing import Dict, Generator, List, Optional, Tuple

import volatility.plugins.windows.handles as handles

from volatility.framework import constants, interfaces, renderers, exceptions, symbols
from volatility.framework.configuration import requirements
from volatility.framework.interfaces import plugins, configuration
from volatility.framework.layers import scanners
from volatility.framework.renderers import format_hints
from volatility.framework.symbols import intermed
from volatility.framework.symbols.windows import extensions

vollog = logging.getLogger(__name__)


# TODO: When python3.5 is no longer supported, make this enum.IntFlag
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


class PoolConstraint:
    """Class to maintain tag/size/index/type information about Pool header tags"""

    def __init__(self,
                 tag: bytes,
                 type_name: str,
                 object_type: Optional[str] = None,
                 page_type: Optional[PoolType] = None,
                 size: Optional[Tuple[Optional[int], Optional[int]]] = None,
                 index: Optional[Tuple[Optional[int], Optional[int]]] = None,
                 alignment: Optional[int] = 1) -> None:
        self.tag = tag
        self.type_name = type_name
        self.object_type = object_type
        self.page_type = page_type
        self.size = size
        self.index = index
        self.alignment = alignment


class PoolScanner(plugins.PluginInterface):
    """A generic pool scanner plugin"""

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.TranslationLayerRequirement(
                name = 'primary', description = 'Memory layer for the kernel', architectures = ["Intel32", "Intel64"]),
            requirements.SymbolTableRequirement(name = "nt_symbols", description = "Windows kernel symbols")
        ]

    @staticmethod
    def is_windows_10(context: interfaces.context.ContextInterface, symbol_table: str) -> bool:
        """Determine if the analyzed sample is Windows 10"""

        # try the primary method based on the pe version in the ISF
        try:
            pe_version = context.symbol_space[symbol_table].metadata.pe_version
            major, minor, _revision, _build = pe_version
            return (major, minor) >= (10, 0)
        except (AttributeError, ValueError):
            vollog.log(constants.LOGLEVEL_VVV, "Windows PE version data is not available")

        # fall back to the backup method, if necessary
        try:
            _symbol = context.symbol_space.get_symbol(symbol_table + constants.BANG + "ObHeaderCookie")
            return True
        except exceptions.SymbolError:
            return False

    @staticmethod
    def is_windows_8_or_later(context: interfaces.context.ContextInterface, layer_name: str, symbol_table: str) -> bool:
        """Determine if the analyzed sample is Windows 8 or later"""

        # try the primary method based on the pe version in the ISF
        try:
            pe_version = context.symbol_space[symbol_table].metadata.pe_version
            major, minor, _revision, _build = pe_version
            return (major, minor) >= (6, 2)
        except (AttributeError, ValueError):
            vollog.log(constants.LOGLEVEL_VVV, "Windows PE version data is not available")

        # fall back to the backup method, if necessary
        kvo = context.memory[layer_name].config['kernel_virtual_offset']
        ntkrnlmp = context.module(symbol_table, layer_name = layer_name, offset = kvo)
        handle_table_type = ntkrnlmp.get_type("_HANDLE_TABLE")
        return not handle_table_type.has_member("HandleCount")

    @staticmethod
    def is_windows_7(context: interfaces.context.ContextInterface, layer_name: str, symbol_table: str) -> bool:
        """Determine if the analyzed sample is Windows 7"""

        # try the primary method based on the pe version in the ISF
        try:
            pe_version = context.symbol_space[symbol_table].metadata.pe_version
            major, minor, _revision, _build = pe_version
            return (major, minor) == (6, 1)
        except (AttributeError, ValueError):
            vollog.log(constants.LOGLEVEL_VVV, "Windows PE version data is not available")

        # fall back to the backup method, if necessary
        kvo = context.memory[layer_name].config['kernel_virtual_offset']
        ntkrnlmp = context.module(symbol_table, layer_name = layer_name, offset = kvo)
        handle_table_type = ntkrnlmp.get_type("_OBJECT_HEADER")
        return (handle_table_type.has_member("TypeIndex")
                and not PoolScanner.is_windows_8_or_later(context, layer_name, symbol_table))

    def _generator(self):

        symbol_table = self.config["nt_symbols"]
        constraints = self.builtin_constraints(symbol_table)

        for constraint, mem_object, header in self.generate_pool_scan(self.context, self.config["primary"],
                                                                      symbol_table, constraints):
            # generate some type-specific info for sanity checking
            if constraint.object_type == "Process":
                name = mem_object.ImageFileName.cast(
                    "string", max_length = mem_object.ImageFileName.vol.count, errors = "replace")
            elif constraint.object_type == "File":
                try:
                    name = mem_object.FileName.String
                except exceptions.PagedInvalidAddressException:
                    vollog.log(constants.LOGLEVEL_VVV, "Skipping file at {0:#x}".format(mem_object.vol.offset))
                    continue
            else:
                name = renderers.NotApplicableValue()

            yield (0, (constraint.type_name, format_hints.Hex(header.vol.offset), header.vol.layer_name, name))

    @staticmethod
    def builtin_constraints(symbol_table: str, tags_filter: List[bytes] = None) -> List[PoolConstraint]:
        """Get built-in PoolConstraints given a list of pool tags.

        The tags_filter is a list of pool tags, and the associated
        PoolConstraints are  returned. If tags_filter is empty or
        not supplied, then all builtin constraints are returned.
        """

        builtins = [
            # atom tables
            PoolConstraint(
                b'AtmT',
                type_name = symbol_table + constants.BANG + "_RTL_ATOM_TABLE",
                size = (200, None),
                page_type = PoolType.PAGED | PoolType.NONPAGED | PoolType.FREE),
            # processes on windows before windows 8
            PoolConstraint(
                b'Pro\xe3',
                type_name = symbol_table + constants.BANG + "_EPROCESS",
                object_type = "Process",
                size = (600, None),
                page_type = PoolType.PAGED | PoolType.NONPAGED | PoolType.FREE),
            # processes on windows starting with windows 8
            PoolConstraint(
                b'Proc',
                type_name = symbol_table + constants.BANG + "_EPROCESS",
                object_type = "Process",
                size = (600, None),
                page_type = PoolType.PAGED | PoolType.NONPAGED | PoolType.FREE),
            # files on windows before windows 8
            PoolConstraint(
                b'Fil\xe5',
                type_name = symbol_table + constants.BANG + "_FILE_OBJECT",
                object_type = "File",
                size = (150, None),
                page_type = PoolType.PAGED | PoolType.NONPAGED | PoolType.FREE),
            # files on windows starting with windows 8
            PoolConstraint(
                b'File',
                type_name = symbol_table + constants.BANG + "_FILE_OBJECT",
                object_type = "File",
                size = (150, None),
                page_type = PoolType.PAGED | PoolType.NONPAGED | PoolType.FREE),
            # mutants on windows before windows 8
            PoolConstraint(
                b'Mut\xe1',
                type_name = symbol_table + constants.BANG + "_KMUTANT",
                object_type = "Mutant",
                size = (64, None),
                page_type = PoolType.PAGED | PoolType.NONPAGED | PoolType.FREE),
            # mutants on windows starting with windows 8
            PoolConstraint(
                b'Muta',
                type_name = symbol_table + constants.BANG + "_KMUTANT",
                object_type = "Mutant",
                size = (64, None),
                page_type = PoolType.PAGED | PoolType.NONPAGED | PoolType.FREE),
            # drivers on windows before windows 8
            PoolConstraint(
                b'Dri\xf6',
                type_name = symbol_table + constants.BANG + "_DRIVER_OBJECT",
                object_type = "Driver",
                size = (248, None),
                page_type = PoolType.PAGED | PoolType.NONPAGED | PoolType.FREE),
            # drivers on windows starting with windows 8
            PoolConstraint(
                b'Driv',
                type_name = symbol_table + constants.BANG + "_DRIVER_OBJECT",
                object_type = "Driver",
                size = (248, None),
                page_type = PoolType.PAGED | PoolType.NONPAGED | PoolType.FREE),
            # kernel modules
            PoolConstraint(
                b'MmLd',
                type_name = symbol_table + constants.BANG + "_LDR_DATA_TABLE_ENTRY",
                size = (76, None),
                page_type = PoolType.PAGED | PoolType.NONPAGED | PoolType.FREE),
            # symlinks on windows before windows 8
            PoolConstraint(
                b'Sym\xe2',
                type_name = symbol_table + constants.BANG + "_OBJECT_SYMBOLIC_LINK",
                object_type = "SymbolicLink",
                size = (72, None),
                page_type = PoolType.PAGED | PoolType.NONPAGED | PoolType.FREE),
            # symlinks on windows starting with windows 8
            PoolConstraint(
                b'Symb',
                type_name = symbol_table + constants.BANG + "_OBJECT_SYMBOLIC_LINK",
                object_type = "SymbolicLink",
                size = (72, None),
                page_type = PoolType.PAGED | PoolType.NONPAGED | PoolType.FREE),
        ]

        if not tags_filter:
            return builtins

        return [constraint for constraint in builtins if constraint.tag in tags_filter]

    @classmethod
    def generate_pool_scan(cls,
                           context: interfaces.context.ContextInterface,
                           layer_name: str,
                           symbol_table: str,
                           constraints: List[PoolConstraint]) \
            -> Generator[Tuple[
                             PoolConstraint, interfaces.objects.ObjectInterface, interfaces.objects.ObjectInterface], None, None]:

        # get the object type map
        type_map = handles.Handles.list_objects(context = context, layer_name = layer_name, symbol_table = symbol_table)

        cookie = handles.Handles.find_cookie(context = context, layer_name = layer_name, symbol_table = symbol_table)

        is_windows_10 = cls.is_windows_10(context = context, symbol_table = symbol_table)
        is_windows_8_or_later = cls.is_windows_8_or_later(
            context = context, layer_name = layer_name, symbol_table = symbol_table)

        # start off with the primary virtual layer
        scan_layer = layer_name

        # switch to a non-virtual layer if necessary
        if not is_windows_10:
            scan_layer = context.memory[scan_layer].config['memory_layer']

        for constraint, header in cls.pool_scan(context, scan_layer, symbol_table, constraints, alignment = 8):

            mem_object = header.get_object(
                type_name = constraint.type_name,
                type_map = type_map,
                use_top_down = is_windows_8_or_later,
                object_type = constraint.object_type,
                native_layer_name = 'primary',
                cookie = cookie)

            if mem_object is None:
                vollog.log(constants.LOGLEVEL_VVV, "Cannot create an instance of {}".format(constraint.type_name))
                continue

            yield constraint, mem_object, header

    @classmethod
    def pool_scan(cls,
                  context: interfaces.context.ContextInterface,
                  layer_name: str,
                  symbol_table: str,
                  pool_constraints: List[PoolConstraint],
                  alignment: int = 8,
                  progress_callback: Optional[constants.ProgressCallback] = None) \
            -> Generator[Tuple[PoolConstraint, interfaces.objects.ObjectInterface], None, None]:
        """Returns the _POOL_HEADER object (based on the symbol_table template) after scanning through layer_name
        returning all headers that match any of the constraints provided.  Only one constraint can be provided per tag"""
        # Setup the pattern
        constraint_lookup = {}  # type: Dict[bytes, List[PoolConstraint]]
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
                is_win_7 = PoolScanner.is_windows_7(context, 'primary', symbol_table)
                if is_win_7:
                    pool_header_json_filename = "poolheader-x64-win7"
                else:
                    pool_header_json_filename = "poolheader-x64"
            else:
                pool_header_json_filename = "poolheader-x86"

            new_table_name = PoolHeaderSymbolTable.create(
                context = context,
                config_path = configuration.path_join(context.symbol_space[symbol_table].config_path, "poolheader"),
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
                        elif (constraint.page_type &
                              PoolType.PAGED) and header.PoolType % 2 == 0 and header.PoolType > 0:
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
        return renderers.TreeGrid([("Tag", str), ("Offset", format_hints.Hex), ("Layer", str), ("Name", str)],
                                  self._generator())
