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
"""Defines layers for containing data.  One layer may combine other layers, map data based on the data itself,
 or map a procedure (such as decryption) across another layer of data."""
import collections.abc
import functools
import logging
import math
import multiprocessing
import traceback
from abc import ABCMeta, abstractmethod
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Tuple, Union

from volatility.framework import constants, exceptions, interfaces

vollog = logging.getLogger(__name__)

IMPORTED_MAGIC = False
try:
    import magic

    IMPORTED_MAGIC = True
    vollog.debug("Imported python-magic, autodetecting compressed files based on content")
except ImportError:
    pass

ProgressValue = Union['DummyProgress', multiprocessing.Value]
IteratorValue = Tuple[List[Tuple[str, int, int]], int]


class ScannerInterface(metaclass = ABCMeta):
    """Class for layer scanners that return locations of particular values from within the data

    These are designed to be given a chunk of data and return a generator which yields
    any found items.  They should NOT perform complex/time-consuming tasks, these should
    be carried out by the consumer of the generator on the items returned.

    They will be provided all *available* data (therefore not necessarily contiguous)
    in ascending offset order, in chunks no larger than chunk_size + overlap where
    overlap is the amount of data read twice once at the end of an earlier chunk and
    once at the start of the next chunk.

    It should be noted that the scanner can maintain state if necessary.
    Scanners should balance the size of chunk based on the amount of time
    scanning the chunk will take (ie, do not set an excessively large chunksize
    and try not to take a significant amount of time in the __call__ method).

    Scanners must NOT return results found *after* self.chunk_size (ie, entirely contained
    within the overlap).  It is the responsibility of the scanner not to return such
    duplicate results.

    Scanners can mark themselves as thread_safe, if they do not require state
    in either their own class or the context.  This will allow the scanner to be run
    in parallel against multiple blocks.
    """
    thread_safe = False

    def __init__(self) -> None:
        self.chunk_size = 0x1000000  # Default to 16Mb chunks
        self.overlap = 0x1000  # A page of overlap by default
        self._context = None  # type: Optional[interfaces.context.ContextInterface]
        self._layer_name = None  # type: Optional[str]

    @property
    def context(self) -> Optional['interfaces.context.ContextInterface']:
        return self._context

    @context.setter
    def context(self, ctx: 'interfaces.context.ContextInterface') -> None:
        """Stores the context locally in case the scanner needs to access the layer"""
        self._context = ctx

    @property
    def layer_name(self) -> Optional[str]:
        return self._layer_name

    @layer_name.setter
    def layer_name(self, layer_name: str) -> None:
        """Stores the layer_name being scanned locally in case the scanner needs to access the layer"""
        self._layer_name = layer_name

    @abstractmethod
    def __call__(self, data: bytes, data_offset: int) -> Iterable[Any]:
        """Searches through a chunk of data for a particular value/pattern/etc
           Always returns an iterator of the same type of object (need not be a volatility object)

           data is the chunk of data to search through
           data_offset is the offset within the layer that the data being searched starts at
        """


class DataLayerInterface(interfaces.configuration.ConfigurableInterface, metaclass = ABCMeta):
    """A Layer that directly holds data (and does not translate it).  This is effectively a leaf node in a layer tree.
    It directly accesses a data source and exposes it within volatility."""

    _direct_metadata = collections.ChainMap({}, {
        'architecture': 'Unknown',
        'os': 'Unknown'
    })  # type: collections.ChainMap

    def __init__(self,
                 context: 'interfaces.context.ContextInterface',
                 config_path: str,
                 name: str,
                 metadata: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(context, config_path)
        self._name = name
        if metadata:
            self._direct_metadata.update(metadata)

    # Standard attributes

    @property
    def name(self) -> str:
        """Returns the layer name"""
        return self._name

    @property
    @abstractmethod
    def maximum_address(self) -> int:
        """Returns the maximum valid address of the space"""

    @property
    @abstractmethod
    def minimum_address(self) -> int:
        """Returns the minimum valid address of the space"""

    @property
    def address_mask(self) -> int:
        """Returns a mask which encapsulates all the actives bit of an address for this layer"""
        return (1 << int(math.ceil(math.log2(self.maximum_address)))) - 1

    @abstractmethod
    def is_valid(self, offset: int, length: int = 1) -> bool:
        """Returns a boolean based on whether the offset is valid or not"""

    @abstractmethod
    def read(self, offset: int, length: int, pad: bool = False) -> bytes:
        """Reads an offset for length bytes and returns 'bytes' (not 'str') of length size

           If there is a fault of any kind (such as a page fault), an exception will be thrown
           unless pad is set, in which case the read errors will be replaced by null characters.
        """

    @abstractmethod
    def write(self, offset: int, data: bytes) -> None:
        """Writes a chunk of data at offset.

           Any unavailable sections in the underlying bases will cause an exception to be thrown.
           Note: Writes are not atomic, therefore some data can be written, even if an exception is thrown.
        """

    def destroy(self) -> None:
        """Allows DataLayers to close any open handles, etc.

           Systems that make use of Data Layers should called destroy when they are done with them.
           This will close all handles, and make the object unreadable
           (exceptions will be thrown using a DataLayer after destruction)"""
        pass

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        """Returns a list of Requirement objects for this type of layer"""
        return []

    @property
    def dependencies(self) -> List[str]:
        """DataLayers must never define on other layers"""
        return []

    # ## General scanning methods

    def scan(self,
             context: interfaces.context.ContextInterface,
             scanner: ScannerInterface,
             progress_callback: constants.ProgressCallback = None,
             sections: Iterable[Tuple[int, int]] = None) -> Iterable[Any]:
        """Scans a Translation layer by chunk

           Note: this will skip missing/unmappable chunks of memory
        """
        if progress_callback is not None and not callable(progress_callback):
            raise TypeError("Progress_callback is not callable")

        scanner = scanner
        scanner.context = context
        scanner.layer_name = self.name

        if sections is None:
            sections = [(self.minimum_address, self.maximum_address - self.minimum_address)]

        sections = list(self._coalesce_sections(sections))

        try:
            progress = DummyProgress()  # type: ProgressValue
            scan_iterator = functools.partial(self._scan_iterator, scanner, sections)
            scan_metric = self._scan_metric(scanner, sections)
            if scanner.thread_safe and constants.PARALLELISM:
                progress = multiprocessing.Manager().Value("Q", 0)
                scan_chunk = functools.partial(self._scan_chunk, scanner, progress)
                with multiprocessing.Pool() as pool:
                    result = pool.map_async(scan_chunk, scan_iterator())
                    while not result.ready():
                        if progress_callback:
                            # Run the progress_callback
                            progress_callback(
                                scan_metric(progress.value),
                                "Scanning {} using {}".format(self.name, scanner.__class__.__name__))
                        # Ensures we don't burn CPU cycles going round in a ready waiting loop
                        # without delaying the user too long between progress updates/results
                        result.wait(0.1)
                    for result_value in result.get():
                        yield from result_value
            else:
                progress = DummyProgress()
                scan_chunk = functools.partial(self._scan_chunk, scanner, progress)
                for value in scan_iterator():
                    if progress_callback:
                        progress_callback(
                            scan_metric(progress.value),
                            "Scanning {} using {}".format(self.name, scanner.__class__.__name__))
                    yield from scan_chunk(value)
        except Exception as e:
            # We don't care the kind of exception, so catch and report on everything, yielding nothing further
            vollog.debug("Scan Failure: {}".format(str(e)))
            vollog.log(constants.LOGLEVEL_VVV,
                       "\n".join(traceback.TracebackException.from_exception(e).format(chain = True)))

    def _coalesce_sections(self, sections: Iterable[Tuple[int, int]]) -> Iterable[Tuple[int, int]]:
        """Take a list of (start, length) sections and coalesce any adjacent sections"""
        result = []  # type: List[Tuple[int, int]]
        position = 0
        for (start, length) in sorted(sections):
            if result and start <= position:
                initial_start, _ = result.pop()
                result.append((initial_start, (start + length) - initial_start))
            else:
                result.append((start, length))
            position = start + length

        while result and result[0] < (self.minimum_address, 0):
            first_start, first_length = result[0]
            if first_start + first_length < self.minimum_address:
                result = result[1:]
            elif first_start < self.minimum_address:
                result[0] = (self.minimum_address, (first_start + first_length) - self.minimum_address)
        while result and result[-1] > (self.maximum_address, 0):
            last_start, last_length = result[-1]
            if last_start > self.maximum_address:
                result.pop()
            elif last_start + last_length > self.maximum_address:
                result[1] = (last_start, self.maximum_address - last_start)
        return result

    def _scan_iterator(self, scanner: 'ScannerInterface',
                       sections: Iterable[Tuple[int, int]]) -> Iterable[IteratorValue]:
        """Iterator that indicates which blocks in the layer are to be read by for the scanning

        Returns a list of blocks (potentially in lower layers) that make up this chunk contiguously.
        Chunks can be no bigger than scanner.chunk_size + scanner.overlap
        DataLayers by default are assumed to have no holes
        """
        for section_start, section_length in sections:
            offset, mapped_offset, length, layer_name = section_start, section_start, section_length, self.name
            while length > 0:
                chunk_size = min(length, scanner.chunk_size + scanner.overlap)
                yield [(layer_name, mapped_offset, chunk_size)], offset + chunk_size
                # It we've got more than the scanner's chunk_size, only move up by the chunk_size
                if chunk_size > scanner.chunk_size:
                    chunk_size -= scanner.overlap
                length -= chunk_size
                mapped_offset += chunk_size
                offset += chunk_size

    # We ignore the type due to the iterator_value, actually it only needs to match the output from _scan_iterator
    def _scan_chunk(self, scanner: 'ScannerInterface', progress: 'ProgressValue',
                    iterator_value: IteratorValue) -> List[Any]:
        data_to_scan, chunk_end = iterator_value
        data = b''
        for layer_name, address, chunk_size in data_to_scan:
            try:
                data += self.context.layers[layer_name].read(address, chunk_size)
            except exceptions.InvalidAddressException:
                vollog.debug("Invalid address in layer {} found scanning {} at address {:x}".format(
                    layer_name, self.name, address))

        progress.value = chunk_end
        return list(scanner(data, chunk_end - len(data)))

    def _scan_metric(self, _scanner: 'ScannerInterface', sections: List[Tuple[int, int]]) -> Callable[[int], float]:

        if not sections:
            raise ValueError("Sections have no size, nothing to scan")
        last_section, last_length = sections[-1]
        min_address, _ = sections[0]
        max_address = last_section + last_length

        def _actual_scan_metric(value: int) -> float:
            return max(0, ((value - min_address) * 100) / (max_address - min_address))

        return _actual_scan_metric

    def build_configuration(self) -> interfaces.configuration.HierarchicalDict:
        config = super().build_configuration()

        # Translation Layers are constructable, and therefore require a class configuration variable
        config["class"] = self.__class__.__module__ + "." + self.__class__.__name__
        return config

    # ## Metadata methods

    @property
    def metadata(self) -> Mapping:
        """Returns a ReadOnly copy of the metadata published by this layer"""
        maps = [self.context.layers[layer_name].metadata for layer_name in self.dependencies]
        return interfaces.objects.ReadOnlyMapping(collections.ChainMap({}, self._direct_metadata, *maps))


class TranslationLayerInterface(DataLayerInterface, metaclass = ABCMeta):
    """Provides a layer that translates or transforms another layer or layers.  Translation layers always depend on
    another layer (typically translating offsets in a virtual offset space into a smaller physical offset space).
    """

    @abstractmethod
    def mapping(self, offset: int, length: int, ignore_errors: bool = False) -> Iterable[Tuple[int, int, int, str]]:
        """Returns a sorted iterable of (offset, mapped_offset, length, layer) mappings

           ignore_errors will provide all available maps with gaps, but their total length may not add up to the requested length
           This allows translation layers to provide maps of contiguous regions in one layer
        """
        return []

    @property
    @abstractmethod
    def dependencies(self) -> List[str]:
        """Returns a list of layer names that this layer translates onto"""
        return []

    ### Translation layer convenience function

    def translate(self, offset: int, ignore_errors: bool = False) -> Tuple[Optional[int], Optional[str]]:
        mapping = self.mapping(offset, 0, ignore_errors)
        if mapping:
            _, mapped_offset, _, layer = list(mapping)[0]
        else:
            if ignore_errors:
                # We should only hit this if we ignored errors, but check anyway
                return None, None
            raise exceptions.InvalidAddressException(self.name, offset,
                                                     "Cannot translate {} in layer {}".format(offset, self.name))
        return mapped_offset, layer

    # ## Read/Write functions for mapped pages

    @functools.lru_cache(maxsize = 512)
    def read(self, offset: int, length: int, pad: bool = False) -> bytes:
        """Reads an offset for length bytes and returns 'bytes' (not 'str') of length size"""
        current_offset = offset
        output = []  # type: List[bytes]
        for (offset, mapped_offset, mapped_length, layer) in self.mapping(offset, length, ignore_errors = pad):
            if not pad and offset > current_offset:
                raise exceptions.InvalidAddressException(
                    self.name, current_offset, "Layer {} cannot map offset: {}".format(self.name, current_offset))
            elif offset > current_offset:
                output += [b"\x00" * (offset - current_offset)]
                current_offset = offset
            elif offset < current_offset:
                raise exceptions.LayerException("Mapping returned an overlapping element")
            if mapped_length > 0:
                output += [self._context.layers.read(layer, mapped_offset, mapped_length, pad)]
            current_offset += mapped_length
        recovered_data = b"".join(output)
        return recovered_data + b"\x00" * (length - len(recovered_data))

    def write(self, offset: int, value: bytes) -> None:
        """Writes a value at offset, distributing the writing across any underlying mapping"""
        current_offset = offset
        length = len(value)
        for (offset, mapped_offset, length, layer) in self.mapping(offset, length):
            if offset > current_offset:
                raise exceptions.InvalidAddressException(
                    self.name, current_offset, "Layer {} cannot map offset: {}".format(self.name, current_offset))
            elif offset < current_offset:
                raise exceptions.LayerException("Mapping returned an overlapping element")
            self._context.layers.write(layer, mapped_offset, value)
            current_offset += length

    # ## Scan implementation with knowledge of pages

    def _scan_iterator(self, scanner: 'ScannerInterface',
                       sections: Iterable[Tuple[int, int]]) -> Iterable[IteratorValue]:
        for (section_start, section_length) in sections:
            for mapped in self.mapping(section_start, section_length, ignore_errors = True):
                offset, mapped_offset, length, layer_name = mapped
                while length > 0:
                    chunk_size = min(length, scanner.chunk_size + scanner.overlap)
                    yield [(layer_name, mapped_offset, chunk_size)], offset + chunk_size
                    # It we've got more than the scanner's chunk_size, only move up by the chunk_size
                    if chunk_size > scanner.chunk_size:
                        chunk_size -= scanner.overlap
                    length -= chunk_size
                    mapped_offset += chunk_size
                    offset += chunk_size


class LayerContainer(collections.abc.Mapping):
    """Container for multiple layers of data"""

    def __init__(self) -> None:
        self._layers = {}  # type: Dict[str, DataLayerInterface]

    def read(self, layer: str, offset: int, length: int, pad: bool = False) -> bytes:
        """Reads from a particular layer at offset for length bytes

           Returns 'bytes' not 'str'
        """
        return self[layer].read(offset, length, pad)

    def write(self, layer: str, offset: int, data: bytes) -> None:
        """Writes to a particular layer at offset for length bytes"""
        self[layer].write(offset, data)

    def add_layer(self, layer: DataLayerInterface) -> None:
        """Adds a layer to memory model

           This will throw an exception if the required dependencies are not met
        """
        if layer.name in self._layers:
            raise exceptions.LayerException("Layer already exists: {}".format(layer.name))
        if isinstance(layer, TranslationLayerInterface):
            missing_list = [sublayer for sublayer in layer.dependencies if sublayer not in self._layers]
            if missing_list:
                raise exceptions.LayerException("Layer {} has unmet dependencies: {}".format(
                    layer.name, ", ".join(missing_list)))
        self._layers[layer.name] = layer

    def del_layer(self, name: str) -> None:
        """Removes the layer called name

           This will throw an exception if other layers depend upon this layer
        """
        for layer in self._layers:
            depend_list = [superlayer for superlayer in self._layers if name in self._layers[layer].dependencies]
            if depend_list:
                raise exceptions.LayerException("Layer {} is depended upon: {}".format(
                    self._layers[layer].name, ", ".join(depend_list)))
        self._layers[name].destroy()
        del self._layers[name]

    def free_layer_name(self, prefix: str = "layer") -> str:
        """Returns an unused layer name to ensure no collision occurs when inserting a layer"""
        count = 1
        while prefix + str(count) in self:
            count += 1
        return prefix + str(count)

    def __getitem__(self, name: str) -> DataLayerInterface:
        """Returns the layer of specified name"""
        return self._layers[name]

    def __len__(self) -> int:
        return len(self._layers)

    def __iter__(self):
        return iter(self._layers)

    def check_cycles(self) -> None:
        """Runs through the available layers and identifies if there are cycles in the DAG"""
        # TODO: Is having a cycle check necessary?


class DummyProgress(object):

    def __init__(self):
        self.value = 0
