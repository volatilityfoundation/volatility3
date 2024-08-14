# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
"""Defines layers for containing data.

One layer may combine other layers, map data based on the data itself,
or map a procedure (such as decryption) across another layer of data.
"""
import collections.abc
import functools
import logging
import math
import multiprocessing
import multiprocessing.managers
import threading
import traceback
import types
import lzma
import json
from abc import ABCMeta, abstractmethod
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Tuple, Union

from volatility3.framework import constants, exceptions, interfaces
from volatility3.framework.interfaces.configuration import path_join

vollog = logging.getLogger(__name__)

ProgressValue = Union["DummyProgress", multiprocessing.managers.ValueProxy]
IteratorValue = Tuple[List[Tuple[str, int, int]], int]


class ScannerInterface(
    interfaces.configuration.VersionableInterface, metaclass=ABCMeta
):
    """Class for layer scanners that return locations of particular values from
    within the data.

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

    _required_framework_version = (2, 0, 0)

    def __init__(self) -> None:
        super().__init__()
        self.chunk_size = 0x1000000  # Default to 16Mb chunks
        self.overlap = 0x1000  # A page of overlap by default
        self._context: Optional[interfaces.context.ContextInterface] = None
        self._layer_name: Optional[str] = None

    @property
    def context(self) -> Optional["interfaces.context.ContextInterface"]:
        return self._context

    @context.setter
    def context(self, ctx: "interfaces.context.ContextInterface") -> None:
        """Stores the context locally in case the scanner needs to access the
        layer."""
        self._context = ctx

    @property
    def layer_name(self) -> Optional[str]:
        return self._layer_name

    @layer_name.setter
    def layer_name(self, layer_name: str) -> None:
        """Stores the layer_name being scanned locally in case the scanner
        needs to access the layer."""
        self._layer_name = layer_name

    @abstractmethod
    def __call__(self, data: bytes, data_offset: int) -> Iterable[Any]:
        """Searches through a chunk of data for a particular value/pattern/etc
        Always returns an iterator of the same type of object (need not be a
        volatility object)

        data is the chunk of data to search through data_offset is the
        offset within the layer that the data being searched starts at
        """


class DataLayerInterface(
    interfaces.configuration.ConfigurableInterface, metaclass=ABCMeta
):
    """A Layer that directly holds data (and does not translate it).

    This is effectively a leaf node in a layer tree. It directly
    accesses a data source and exposes it within volatility.
    """

    _direct_metadata: Mapping = {"architecture": "Unknown", "os": "Unknown"}

    def __init__(
        self,
        context: "interfaces.context.ContextInterface",
        config_path: str,
        name: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__(context, config_path)
        self._name = name
        self._metadata = metadata or {}

    # Standard attributes

    @property
    def name(self) -> str:
        """Returns the layer name."""
        return self._name

    @property
    @abstractmethod
    def maximum_address(self) -> int:
        """Returns the maximum valid address of the space."""

    @property
    @abstractmethod
    def minimum_address(self) -> int:
        """Returns the minimum valid address of the space."""

    @property
    def address_mask(self) -> int:
        """Returns a mask which encapsulates all the active bits of an address
        for this layer."""
        return (1 << int(math.ceil(math.log2(self.maximum_address)))) - 1

    @abstractmethod
    def is_valid(self, offset: int, length: int = 1) -> bool:
        """Returns a boolean based on whether the entire chunk of data (from
        offset to length) is valid or not.

        Args:
            offset: The address to start determining whether bytes are readable/valid
            length: The number of bytes from offset of which to test the validity

        Returns:
             Whether the bytes are valid and accessible
        """

    @abstractmethod
    def read(self, offset: int, length: int, pad: bool = False) -> bytes:
        """Reads an offset for length bytes and returns 'bytes' (not 'str') of
        length size.

        If there is a fault of any kind (such as a page fault), an exception will be thrown
        unless pad is set, in which case the read errors will be replaced by null characters.

        Args:
            offset: The offset at which to being reading within the layer
            length: The number of bytes to read within the layer
            pad: A boolean indicating whether exceptions should be raised or bad bytes replaced with null characters

        Returns:
            The bytes read from the layer, starting at offset for length bytes
        """

    @abstractmethod
    def write(self, offset: int, data: bytes) -> None:
        """Writes a chunk of data at offset.

        Any unavailable sections in the underlying bases will cause an exception to be thrown.
        Note: Writes are not guaranteed atomic, therefore some data may have been written, even if an exception is thrown.
        """

    def destroy(self) -> None:
        """Causes a DataLayer to close any open handles, etc.

        Systems that make use of Data Layers should call destroy when
        they are done with them. This will close all handles, and make
        the object unreadable (exceptions will be thrown using a
        DataLayer after destruction)
        """
        pass

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        """Returns a list of Requirement objects for this type of layer."""
        return super().get_requirements()

    @property
    def dependencies(self) -> List[str]:
        """A list of other layer names required by this layer.

        Note:
            DataLayers must never define other layers
        """
        return []

    # ## General scanning methods

    def scan(
        self,
        context: interfaces.context.ContextInterface,
        scanner: ScannerInterface,
        progress_callback: constants.ProgressCallback = None,
        sections: Iterable[Tuple[int, int]] = None,
    ) -> Iterable[Any]:
        """Scans a Translation layer by chunk.

        Note: this will skip missing/unmappable chunks of memory

        Args:
             context: The context containing the data layer
             scanner: The constructed Scanner object to be applied
             progress_callback: Method that is called periodically during scanning to update progress
             sections: A list of (start, size) tuples defining the portions of the layer to scan

        Returns:
             The output iterable from the scanner object having been run against the layer
        """
        if progress_callback is not None and not callable(progress_callback):
            raise TypeError("Progress_callback is not callable")

        scanner.context = context
        scanner.layer_name = self.name

        if sections is None:
            sections = [
                (self.minimum_address, self.maximum_address - self.minimum_address)
            ]

        sections = list(self._coalesce_sections(sections))

        try:
            progress: ProgressValue = DummyProgress()
            scan_iterator = functools.partial(self._scan_iterator, scanner, sections)
            scan_metric = self._scan_metric(scanner, sections)
            if (
                not scanner.thread_safe
                or constants.PARALLELISM == constants.Parallelism.Off
            ):
                progress = DummyProgress()
                scan_chunk = functools.partial(self._scan_chunk, scanner, progress)
                for value in scan_iterator():
                    if progress_callback:
                        progress_callback(
                            scan_metric(progress.value),
                            f"Scanning {self.name} using {scanner.__class__.__name__}",
                        )
                    yield from scan_chunk(value)
            else:
                progress = multiprocessing.Manager().Value("Q", 0)
                parallel_module: types.ModuleType = multiprocessing
                if constants.PARALLELISM == constants.Parallelism.Threading:
                    progress = DummyProgress()
                    parallel_module = threading
                scan_chunk = functools.partial(self._scan_chunk, scanner, progress)
                with parallel_module.Pool() as pool:
                    result = pool.map_async(scan_chunk, scan_iterator())
                    while not result.ready():
                        if progress_callback:
                            # Run the progress_callback
                            progress_callback(
                                scan_metric(progress.value),
                                f"Scanning {self.name} using {scanner.__class__.__name__}",
                            )
                        # Ensures we don't burn CPU cycles going round in a ready waiting loop
                        # without delaying the user too long between progress updates/results
                        result.wait(0.1)
                    for result_value in result.get():
                        yield from result_value
        except Exception as e:
            # We don't care the kind of exception, so catch and report on everything, yielding nothing further
            vollog.debug(f"Scan Failure: {str(e)}")
            vollog.log(
                constants.LOGLEVEL_VVV,
                "\n".join(
                    traceback.TracebackException.from_exception(e).format(chain=True)
                ),
            )

    def _coalesce_sections(
        self, sections: Iterable[Tuple[int, int]]
    ) -> Iterable[Tuple[int, int]]:
        """Take a list of (start, length) sections and coalesce any adjacent
        sections."""
        result: List[Tuple[int, int]] = []
        position = 0
        for start, length in sorted(sections):
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
                result[0] = (
                    self.minimum_address,
                    (first_start + first_length) - self.minimum_address,
                )
        while result and result[-1] > (self.maximum_address, 0):
            last_start, last_length = result[-1]
            if last_start > self.maximum_address:
                result.pop()
            elif last_start + last_length > self.maximum_address:
                result[1] = (last_start, self.maximum_address - last_start)
        return result

    def _scan_iterator(
        self, scanner: "ScannerInterface", sections: Iterable[Tuple[int, int]]
    ) -> Iterable[IteratorValue]:
        """Iterator that indicates which blocks in the layer are to be read by
        for the scanning.

        Returns a list of blocks (potentially in lower layers) that make
        up this chunk contiguously. Chunks can be no bigger than
        scanner.chunk_size + scanner.overlap DataLayers by default are
        assumed to have no holes
        """
        for section_start, section_length in sections:
            offset, mapped_offset, length, layer_name = (
                section_start,
                section_start,
                section_length,
                self.name,
            )
            while length > 0:
                chunk_size = min(length, scanner.chunk_size + scanner.overlap)
                yield [(layer_name, mapped_offset, chunk_size)], offset + chunk_size
                # If we've got more than the scanner's chunk_size, only move up by the chunk_size
                if chunk_size > scanner.chunk_size:
                    chunk_size -= scanner.overlap
                length -= chunk_size
                mapped_offset += chunk_size
                offset += chunk_size

    # We ignore the type due to the iterator_value, actually it only needs to match the output from _scan_iterator
    def _scan_chunk(
        self,
        scanner: "ScannerInterface",
        progress: "ProgressValue",
        iterator_value: IteratorValue,
    ) -> List[Any]:
        data_to_scan, chunk_end = iterator_value
        data = b""
        for layer_name, address, chunk_size in data_to_scan:
            try:
                data += self.context.layers[layer_name].read(address, chunk_size)
            except exceptions.InvalidAddressException:
                vollog.debug(
                    "Invalid address in layer {} found scanning {} at address {:x}".format(
                        layer_name, self.name, address
                    )
                )

        if len(data) > scanner.chunk_size + scanner.overlap:
            vollog.debug(f"Scan chunk too large: {hex(len(data))}")

        progress.value = chunk_end
        return list(scanner(data, chunk_end - len(data)))

    def _scan_metric(
        self, _scanner: "ScannerInterface", sections: List[Tuple[int, int]]
    ) -> Callable[[int], float]:
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
        """Returns a ReadOnly copy of the metadata published by this layer."""
        maps = [
            self.context.layers[layer_name].metadata for layer_name in self.dependencies
        ]
        return interfaces.objects.ReadOnlyMapping(
            collections.ChainMap(self._metadata, self._direct_metadata, *maps)
        )


class TranslationLayerInterface(DataLayerInterface, metaclass=ABCMeta):
    """Provides a layer that translates or transforms another layer or layers.

    Translation layers always depend on another layer (typically
    translating offsets in a virtual offset space into a smaller
    physical offset space).
    """

    @abstractmethod
    def mapping(
        self, offset: int, length: int, ignore_errors: bool = False
    ) -> Iterable[Tuple[int, int, int, int, str]]:
        """Returns a sorted iterable of (offset, sublength, mapped_offset, mapped_length, layer)
        mappings.

        ignore_errors will provide all available maps with gaps, but
        their total length may not add up to the requested length This
        allows translation layers to provide maps of contiguous regions
        in one layer
        """
        return []

    @property
    @abstractmethod
    def dependencies(self) -> List[str]:
        """Returns a list of layer names that this layer translates onto."""
        return []

    def _decode_data(
        self, data: bytes, mapped_offset: int, offset: int, output_length: int
    ) -> bytes:
        """Decodes any necessary data.  Note, additional data may need to be read from the lower layer, such as lookup
        tables or similar.  The data provided to this layer is purely that data which encompasses the requested data
        range.

        Args:
            data: The bytes of data necessary for decoding
            mapped_offset: The offset in the underlying layer where the data would begin
            offset: The offset in the higher-layer where the data would begin
            output_length: The expected length of the returned data

        Returns:
             The data to be read from the underlying layer."""
        return data

    def _encode_data(
        self, layer_name: str, mapped_offset: int, offset: int, value: bytes
    ) -> bytes:
        """Encodes any necessary data.

        Args:
            layer_name: The layer to write data back to
            mapped_offset: The offset in the underlying layer where the data would begin
            offset: The offset in the higher-layer where the data would begin
            value: The new value to encode

        Returns:
             The data to be rewritten at mapped_offset."""
        return value

    # ## Read/Write functions for mapped pages

    def _access_virtmap_cache(self, section: Tuple[int, int]) -> Optional[list]:
        """Checks and loads the virtmap cache.

        The virtmap cache corresponds to a previous _scan_iterator
        output, typically loaded from a file.
        Args:
            sections: sections (start, size) to retrieve from the cache
        Returns:
            A list containing mappings for a specific section of this layer"""

        # Check if layer is fully constructed first
        if self.config.get("class") and self.context.config.get(
            path_join("virtmap_cache", "filepath")
        ):
            filepath = self.context.config[path_join("virtmap_cache", "filepath")]
            layers_classes = self.context.config[
                path_join("virtmap_cache", "layers_classes")
            ]

            # Exact match only, even if a requested section would *fit*
            # inside one available in the cache.
            if (
                self.config["class"] in layers_classes
                and str(section)
                in self.context.config[
                    path_join(
                        "virtmap_cache", "sections_per_layer", self.config["class"]
                    )
                ]
            ):
                # Avoid decompressing and deserializing the file
                # more than once. Saves time, but costs more RAM.
                if not hasattr(self, "_virtmap_cache_dict"):
                    with open(filepath, "rb") as f:
                        raw_json = lzma.decompress(f.read())
                        # Can be sped up via the orjson library
                        self._virtmap_cache_dict = json.loads(raw_json)

                vollog.log(
                    constants.LOGLEVEL_VVV,
                    f"Applying virtmap cache to section {section} of layer {self.config['class']}",
                )
                return self._virtmap_cache_dict[self.config["class"]][str(section)]
        return None

    @functools.lru_cache(maxsize=512)
    def read(self, offset: int, length: int, pad: bool = False) -> bytes:
        """Reads an offset for length bytes and returns 'bytes' (not 'str') of
        length size."""
        current_offset = offset
        output: bytes = b""
        for (
            layer_offset,
            sublength,
            mapped_offset,
            mapped_length,
            layer,
        ) in self.mapping(offset, length, ignore_errors=pad):
            if not pad and layer_offset > current_offset:
                raise exceptions.InvalidAddressException(
                    self.name,
                    current_offset,
                    f"Layer {self.name} cannot map offset: {current_offset}",
                )
            elif layer_offset > current_offset:
                output += b"\x00" * (layer_offset - current_offset)
                current_offset = layer_offset
            # The layer_offset can be less than the current_offset in non-linearly mapped layers
            # it does not suggest an overlap, but that the data is in an encoded block
            if mapped_length > 0:
                unprocessed_data = self._context.layers.read(
                    layer, mapped_offset, mapped_length, pad
                )
                processed_data = self._decode_data(
                    unprocessed_data, mapped_offset, layer_offset, sublength
                )
                if len(processed_data) != sublength:
                    raise ValueError(
                        "ProcessedData length does not match expected length of chunk"
                    )
                output += processed_data
                current_offset += sublength
        return output + (b"\x00" * (length - len(output)))

    def write(self, offset: int, value: bytes) -> None:
        """Writes a value at offset, distributing the writing across any
        underlying mapping."""
        current_offset = offset
        length = len(value)
        for (
            layer_offset,
            sublength,
            mapped_offset,
            mapped_length,
            layer,
        ) in self.mapping(offset, length):
            if layer_offset > current_offset:
                raise exceptions.InvalidAddressException(
                    self.name,
                    current_offset,
                    f"Layer {self.name} cannot map offset: {current_offset}",
                )

            value_chunk = value[
                layer_offset - offset : layer_offset - offset + sublength
            ]
            new_data = self._encode_data(
                layer, mapped_offset, layer_offset, value_chunk
            )
            self._context.layers.write(layer, mapped_offset, new_data)

            current_offset += len(new_data)

    def _scan_iterator(
        self,
        scanner: "ScannerInterface",
        sections: Iterable[Tuple[int, int]],
        linear: bool = False,
    ) -> Iterable[IteratorValue]:
        """Iterator that indicates which blocks in the layer are to be read by
        for the scanning.

        Returns a list of blocks (potentially in lower layers) that make
        up this chunk contiguously. Chunks can be no bigger than
        scanner.chunk_size + scanner.overlap DataLayers by default are
        assumed to have no holes
        """
        for section_start, section_length in sections:
            # Check the virtmap cache and use it if available
            cache = self._access_virtmap_cache((section_start, section_length))
            if cache:
                for map in cache:
                    yield map
                continue
            output: List[Tuple[str, int, int]] = []

            # Hold the offsets of each chunk (including how much has been filled)
            chunk_start = chunk_position = 0

            # For each section, find out which bits of its exists and where they map to
            # This is faster than cutting the entire space into scan_chunk sized blocks and then
            # finding out what exists (particularly if most of the space isn't mapped)
            for mapped in self.mapping(
                section_start, section_length, ignore_errors=True
            ):
                offset, sublength, mapped_offset, mapped_length, layer_name = mapped

                # Setup the variables for this block
                block_start = offset
                block_end = offset + sublength

                # Setup the necessary bits for non-linear mappings
                # For linear we give one layer down and mapped offsets (therefore the conversion)
                # This saves an tiny amount of time not have to redo lookups we've already done
                # For non-linear layers, we give the layer name and the offset in the layer name
                # so that the read/conversion occurs properly
                conversion = mapped_offset - offset if linear else 0
                return_name = layer_name if linear else self.name

                # If this isn't contiguous, start a new chunk
                if chunk_position < block_start:
                    yield output, chunk_position
                    output = []
                    chunk_start = chunk_position = block_start

                # Halfway through a chunk, finish the chunk, then take more
                if chunk_position != chunk_start:
                    chunk_size = min(
                        chunk_position - chunk_start,
                        scanner.chunk_size + scanner.overlap,
                    )
                    output += [(return_name, chunk_position + conversion, chunk_size)]
                    chunk_start = chunk_position + chunk_size
                    chunk_position = chunk_start

                # Pack chunks, if we're enter the loop (starting a new chunk) and there's already chunk there, ship it
                for chunk_start in range(chunk_position, block_end, scanner.chunk_size):
                    if output:
                        yield output, chunk_position
                        output = []
                        chunk_position = chunk_start
                    # Take from chunk_position as far as the block can go,
                    # or as much left of a scanner chunk as we can
                    chunk_size = min(
                        block_end - chunk_position,
                        scanner.chunk_size
                        + scanner.overlap
                        - (chunk_position - chunk_start),
                    )
                    output += [(return_name, chunk_position + conversion, chunk_size)]
                    chunk_start = chunk_position + chunk_size
                    chunk_position = chunk_start

            # Ship anything that might be left
            if output:
                yield output, chunk_position


class LayerContainer(collections.abc.Mapping):
    """Container for multiple layers of data."""

    def __init__(self) -> None:
        self._layers: Dict[str, DataLayerInterface] = {}

    def read(self, layer: str, offset: int, length: int, pad: bool = False) -> bytes:
        """Reads from a particular layer at offset for length bytes.

        Returns 'bytes' not 'str'

        Args:
            layer: The name of the layer to read from
            offset: Where to begin reading within the layer
            length: How many bytes to read from the layer
            pad: Whether to raise exceptions or return null bytes when errors occur

        Returns:
            The result of reading from the requested layer
        """
        return self[layer].read(offset, length, pad)

    def __eq__(self, other):
        return dict(self) == dict(other)

    def write(self, layer: str, offset: int, data: bytes) -> None:
        """Writes to a particular layer at offset for length bytes."""
        self[layer].write(offset, data)

    def add_layer(self, layer: DataLayerInterface) -> None:
        """Adds a layer to memory model.

        This will throw an exception if the required dependencies are not met

        Args:
            layer: the layer to add to the list of layers (based on layer.name)
        """
        if layer.name in self._layers:
            raise exceptions.LayerException(
                layer.name, f"Layer already exists: {layer.name}"
            )
        if isinstance(layer, TranslationLayerInterface):
            missing_list = [
                sublayer
                for sublayer in layer.dependencies
                if sublayer not in self._layers
            ]
            if missing_list:
                raise exceptions.LayerException(
                    layer.name,
                    f"Layer {layer.name} has unmet dependencies: {', '.join(missing_list)}",
                )
        self._layers[layer.name] = layer

    def del_layer(self, name: str) -> None:
        """Removes the layer called name.

        This will throw an exception if other layers depend upon this layer

        Args:
            name: The name of the layer to delete
        """
        for layer in self._layers:
            if name in self._layers[layer].dependencies:
                raise exceptions.LayerException(
                    self._layers[layer].name,
                    f"Layer {self._layers[layer].name} is depended upon by {layer}",
                )
        # Otherwise, wipe out the layer
        self._layers[name].destroy()
        del self._layers[name]

    def free_layer_name(self, prefix: str = "layer") -> str:
        """Returns an unused layer name to ensure no collision occurs when
        inserting a layer.

        Args:
            prefix: A descriptive string with which to prefix the layer name

        Returns:
            A string containing a name, prefixed with prefix, not currently in use within the LayerContainer
        """
        if prefix not in self:
            return prefix
        count = 1
        while f"{prefix}_{count}" in self:
            count += 1
        return f"{prefix}_{count}"

    def __getitem__(self, name: str) -> DataLayerInterface:
        """Returns the layer of specified name."""
        return self._layers[name]

    def __len__(self) -> int:
        return len(self._layers)

    def __iter__(self):
        return iter(self._layers)

    def check_cycles(self) -> None:
        """Runs through the available layers and identifies if there are cycles
        in the DAG."""
        # TODO: Is having a cycle check necessary?
        raise NotImplementedError("Cycle checking has not yet been implemented")


class DummyProgress(object):
    """A class to emulate Multiprocessing/threading Value objects."""

    def __init__(self) -> None:
        self.value = 0
