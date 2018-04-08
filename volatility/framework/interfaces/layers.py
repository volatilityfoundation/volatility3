"""Defines layers for containing data.  One layer may combine other layers, map data based on the data itself,
 or map a procedure (such as decryption) across another layer of data."""
import functools
import logging
import math
import multiprocessing
import traceback
import typing
from abc import ABCMeta, abstractmethod

import collections.abc

from volatility.framework import constants, exceptions, validity, interfaces
from volatility.framework.interfaces import configuration, context

vollog = logging.getLogger(__name__)

IMPORTED_MAGIC = False
try:
    import magic

    IMPORTED_MAGIC = True
    vollog.debug("Imported python-magic, autodetecting compressed files based on content")
except ImportError:
    pass

ProgressValue = typing.Union['DummyProgress', multiprocessing.Value]


class ScannerInterface(validity.ValidityRoutines, metaclass = ABCMeta):
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

    Scanners can mark themselves as thread_safe, if they do not require state
    in either their own class or the context.  This will allow the scanner to be run
    in parallel against multiple blocks.
    """
    thread_safe = False

    def __init__(self) -> None:
        self.chunk_size = 0x1000000  # Default to 16Mb chunks
        self.overlap = 0x1000  # A page of overlap by default
        self._context = None
        self._layer_name = None  # type: typing.Optional[str]

    @property
    def context(self) -> 'interfaces.context.ContextInterface':
        return self._context

    @context.setter
    def context(self, ctx: 'interfaces.context.ContextInterface') -> None:
        """Stores the context locally in case the scanner needs to access the layer"""
        self._context = self._check_type(ctx, context.ContextInterface)

    @property
    def layer_name(self) -> str:
        return self._layer_name

    @layer_name.setter
    def layer_name(self, layer_name: str) -> None:
        """Stores the layer_name being scanned locally in case the scanner needs to access the layer"""
        self._layer_name = self._check_type(layer_name, str)

    @abstractmethod
    def __call__(self, data: bytes, data_offset: int) -> typing.Iterable[typing.Any]:
        """Searches through a chunk of data for a particular value/pattern/etc
           Always returns an iterator of the same type of object (need not be a volatility object)

           data is the chunk of data to search through
           data_offset is the offset within the layer that the data being searched starts at
        """


class DataLayerInterface(configuration.ConfigurableInterface, validity.ValidityRoutines, metaclass = ABCMeta):
    """A Layer that directly holds data (and does not translate it).  This is effectively a leaf node in a layer tree.
    It directly accesses a data source and exposes it within volatility."""

    _architecture = "Unknown"

    def __init__(self,
                 context: 'interfaces.context.ContextInterface',
                 config_path: str,
                 name: str,
                 os: str = "Unknown") -> None:
        super().__init__(context, config_path)
        self._name = self._check_type(name, str)
        self._os = self._check_type(os, str)

    # Memory specific attributes

    @property
    def architecture(self) -> str:
        """The architecutre of the TranslationLayer

        This cannot be modified after construction outside of the class
        """
        return self._architecture

    @property
    def os(self) -> str:
        """The operating system related to the TranslationLayer"""
        return self._os

    @os.setter
    def os(self, value: str) -> None:
        """Sets the operating system of the TranslationLayer"""
        self._os = self._check_type(value, str)

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
    def get_requirements(cls) -> typing.List[interfaces.configuration.RequirementInterface]:
        """Returns a list of Requirement objects for this type of layer"""
        return []

    @property
    def dependencies(self) -> typing.List[str]:
        """DataLayers must never define on other layers"""
        return []

    # ## General scanning methods

    def scan(self,
             context: interfaces.context.ContextInterface,
             scanner: ScannerInterface,
             progress_callback: validity.ProgressCallback = None,
             min_address: typing.Optional[int] = None,
             max_address: typing.Optional[int] = None) -> typing.Iterable[typing.Any]:
        """Scans a Translation layer by chunk

           Note: this will skip missing/unmappable chunks of memory
        """
        if progress_callback is not None and not callable(progress_callback):
            raise TypeError("Progress_callback is not callable")

        scanner = self._check_type(scanner, ScannerInterface)
        scanner.context = context
        scanner.layer_name = self.name

        if min_address is None:
            min_address = self.minimum_address
        if min_address > self.maximum_address:
            raise ValueError("Minimum address cannot be larger than the maximum address of the space")
        if max_address is None:
            max_address = self.maximum_address
        if max_address < self.minimum_address:
            raise ValueError("Maximum address cannot be smaller than the minimum address of the space")

        min_address = max(self.minimum_address, min_address)
        max_address = min(self.maximum_address, max_address)

        try:
            progress = DummyProgress()  # type: ProgressValue
            scan_iterator = functools.partial(self._scan_iterator, scanner, min_address, max_address)
            scan_metric = functools.partial(self._scan_metric, scanner, min_address, max_address)
            if scanner.thread_safe and not constants.DISABLE_MULTITHREADED_SCANNING:
                progress = multiprocessing.Manager().Value("Q", 0)
                scan_chunk = functools.partial(self._scan_chunk, scanner, min_address, max_address, progress)
                with multiprocessing.Pool() as pool:
                    result = pool.map_async(scan_chunk, scan_iterator())
                    while not result.ready():
                        if progress_callback:
                            # Run the progress_callback
                            progress_callback(scan_metric(progress.value),
                                              "Scanning {} using {}".format(self.name, scanner.__class__.__name__))
                        # Ensures we don't burn CPU cycles going round in a ready waiting loop
                        # without delaying the user too long between progress updates/results
                        result.wait(0.1)
                    for value in result.get():
                        yield from value
            else:
                progress = DummyProgress()
                scan_chunk = functools.partial(self._scan_chunk, scanner, min_address, max_address, progress)
                for value in scan_iterator():
                    if progress_callback:
                        progress_callback(scan_metric(progress.value),
                                          "Scanning {} using {}".format(self.name, scanner.__class__.__name__))
                    yield from scan_chunk(value)
        except Exception as e:
            # We don't care the kind of exception, so catch and report on everything, yielding nothing further
            vollog.debug("Scan Failure: {}".format(str(e)))
            vollog.log(constants.LOGLEVEL_VVV,
                       "\n".join(traceback.TracebackException.from_exception(e).format(chain = True)))

    def _scan_iterator(self,
                       scanner: 'ScannerInterface',
                       min_address: int,
                       max_address: int) -> typing.Iterable[typing.Any]:
        return range(min_address, max_address, scanner.chunk_size)

    def _scan_chunk(self,
                    scanner: 'ScannerInterface',
                    min_address: int,
                    max_address: int,
                    progress: ProgressValue,
                    iterator_value: typing.Any) -> typing.List[typing.Any]:
        length = min(scanner.chunk_size + scanner.overlap, max_address - iterator_value)
        chunk = self.read(iterator_value, length)
        # Don't include the overlaps, or we'll go over 100%
        progress.value += min(scanner.chunk_size, max_address - iterator_value)
        return list(scanner(chunk, iterator_value))

    def _scan_metric(self,
                     _scanner: 'ScannerInterface',
                     min_address: int,
                     max_address: int,
                     value: int) -> float:
        return max(0, (value * 100) / (max_address - min_address))

    def build_configuration(self) -> interfaces.configuration.HierarchicalDict:
        config = super().build_configuration()

        # Translation Layers are constructable, and therefore require a class configuration variable
        config["class"] = self.__class__.__module__ + "." + self.__class__.__name__
        return config


class TranslationLayerInterface(DataLayerInterface, metaclass = ABCMeta):
    """Provides a layer that translates or transforms another layer or layers.  Translation layers always depend on
    another layer (typically translating offsets in a virtual offset space into a smaller physical offset space).
    """
    # Unfortunately class attributes can't easily be inheritted from parent classes
    provides = {"type": "interface"}

    @abstractmethod
    def mapping(self,
                offset: int,
                length: int,
                ignore_errors: bool = False) -> typing.Iterable[typing.Tuple[int, int, int, str]]:
        """Returns a sorted iterable of (offset, mapped_offset, length, layer) mappings

           ignore_errors will provide all available maps with gaps, but their total length may not add up to the requested length
           This allows translation layers to provide maps of contiguous regions in one layer
        """
        return []

    @property
    @abstractmethod
    def dependencies(self) -> typing.List[str]:
        """Returns a list of layer names that this layer translates onto"""
        return []

    ### Translation layer convenience function

    def translate(self, offset: int, ignore_errors: bool = False) \
            -> typing.Tuple[typing.Optional[int], typing.Optional[str]]:
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

    def read(self, offset: int, length: int, pad: bool = False) -> bytes:
        """Reads an offset for length bytes and returns 'bytes' (not 'str') of length size"""
        current_offset = offset
        output = []  # type: typing.List[bytes]
        for (offset, mapped_offset, length, layer) in self.mapping(offset, length, ignore_errors = pad):
            if not pad and offset > current_offset:
                raise exceptions.InvalidAddressException(self.name, current_offset,
                                                         "Layer {} cannot map offset: {}".format(self.name,
                                                                                                 current_offset))
            elif offset > current_offset:
                output += [b"\x00" * (current_offset - offset)]
                current_offset = offset
            elif offset < current_offset:
                raise exceptions.LayerException("Mapping returned an overlapping element")
            output += [self._context.memory.read(layer, mapped_offset, length, pad)]
            current_offset += length
        recovered_data = b"".join(output)
        return recovered_data + b"\x00" * (length - len(recovered_data))

    def write(self, offset: int, value: bytes) -> None:
        """Writes a value at offset, distributing the writing across any underlying mapping"""
        current_offset = offset
        length = len(value)
        for (offset, mapped_offset, length, layer) in self.mapping(offset, length):
            if offset > current_offset:
                raise exceptions.InvalidAddressException(self.name, current_offset,
                                                         "Layer {} cannot map offset: {}".format(self.name,
                                                                                                 current_offset))
            elif offset < current_offset:
                raise exceptions.LayerException("Mapping returned an overlapping element")
            self._context.memory.write(layer, mapped_offset, length)
            current_offset += length

    # ## Scan implementation with knowledge of pages

    def _scan_chunk(self,
                    scanner: 'interfaces.layers.ScannerInterface',
                    min_address: int,
                    max_address: int,
                    progress: ProgressValue,
                    iterator_value: typing.Any) -> typing.List[typing.Any]:
        size_to_scan = min(max_address - min_address, scanner.chunk_size + scanner.overlap)
        result = []  # type: typing.List[typing.Any]
        for map in self.mapping(iterator_value, size_to_scan, ignore_errors = True):
            offset, mapped_offset, length, layer = map
            progress.value += length
            chunk = self._context.memory.read(layer, mapped_offset, length)
            result += [x for x in scanner(chunk, offset)]
        return result


class Memory(validity.ValidityRoutines, collections.abc.Mapping):
    """Container for multiple layers of data"""

    def __init__(self) -> None:
        self._layers = {}  # type: typing.Dict[str, DataLayerInterface]

    def read(self,
             layer: str,
             offset: int,
             length: int,
             pad: bool = False):
        """Reads from a particular layer at offset for length bytes

           Returns 'bytes' not 'str'
        """
        return self[layer].read(offset, length, pad)

    def write(self,
              layer: str,
              offset: int,
              data: bytes) -> None:
        """Writes to a particular layer at offset for length bytes"""
        self[layer].write(offset, data)

    def add_layer(self, layer: DataLayerInterface) -> None:
        """Adds a layer to memory model

           This will throw an exception if the required dependencies are not met
        """
        self._check_type(layer, DataLayerInterface)
        if isinstance(layer, TranslationLayerInterface):
            if layer.name in self._layers:
                raise exceptions.LayerException("Layer already exists: {}".format(layer.name))
            missing_list = [sublayer for sublayer in layer.dependencies if sublayer not in self._layers]
            if missing_list:
                raise exceptions.LayerException(
                    "Layer {} has unmet dependencies: {}".format(layer.name, ", ".join(missing_list)))
        self._layers[layer.name] = layer

    def del_layer(self, name: str) -> None:
        """Removes the layer called name

           This will throw an exception if other layers depend upon this layer
        """
        for layer in self._layers:
            depend_list = [superlayer for superlayer in self._layers if name in self._layers[layer].dependencies]
            if depend_list:
                raise exceptions.LayerException(
                    "Layer {} is depended upon: {}".format(self._layers[layer].name, ", ".join(depend_list)))
        self._layers[name].destroy()
        del self._layers[name]

    def free_layer_name(self, prefix: str = "layer") -> str:
        """Returns an unused layer name to ensure no collision occurs when inserting a layer"""
        self._check_type(prefix, str)

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
