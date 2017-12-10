import typing
from abc import ABCMeta, abstractmethod
from bisect import bisect_right

from volatility.framework import exceptions, interfaces
from volatility.framework.configuration import requirements


class SegmentedLayer(interfaces.layers.TranslationLayerInterface, metaclass = ABCMeta):
    """A class to handle a single run-based layer-to-layer mapping

       In the documentation "mapped address" or "mapped offset" refers to an offset once it has been mapped to the underlying layer
    """

    def __init__(self,
                 context: interfaces.configuration.ContextInterface,
                 config_path: str,
                 name: str) -> None:
        super().__init__(context, config_path = config_path, name = name)

        self._base_layer = self.config["base_layer"]
        self._segments = []  # type: typing.List[typing.Tuple[int, int, int]]
        self._minaddr = None  # type: typing.Optional[int]
        self._maxaddr = None  # type: typing.Optional[int]

        self._load_segments()

    @abstractmethod
    def _load_segments(self) -> None:
        """Populates the _segments variable

           Segments must be (address, mapped address, length) and must be sorted by address when this method exits
        """

    def is_valid(self, offset: int, length: int = 1) -> bool:
        """Returns whether the address offset can be translated to a valid address"""
        try:
            return all([self._context.memory[self._base_layer].is_valid(mapped_offset) for _i, mapped_offset, _i, _s in
                        self.mapping(offset, length)])
        except exceptions.InvalidAddressException:
            return False

    def _find_segment(self, offset: int, next: bool = False) -> typing.Tuple[int, int, int]:
        """Finds the segment containing a given offset

           Returns the segment tuple (offset, mapped_offset, length)
        """

        if not self._segments:
            self._load_segments()

        # Find rightmost value less than or equal to x
        i = bisect_right(self._segments, (offset, self.context.memory[self._base_layer].maximum_address))
        if i:
            if not next:
                segment = self._segments[i - 1]
                if segment[0] <= offset < segment[0] + segment[2]:
                    return segment
            else:
                if i < len(self._segments):
                    return self._segments[i]
        raise exceptions.InvalidAddressException(self.name, offset, "Invalid address at {:0x}".format(offset))

    def mapping(self, offset: int, length: int, ignore_errors: bool = False) \
            -> typing.Iterable[typing.Tuple[int, int, int, str]]:
        """Returns a sorted iterable of (offset, mapped_offset, length, layer) mappings"""
        done = False
        current_offset = offset
        while not done:
            try:
                # Search for the appropriate segment that contains the current_offset
                logical_offset, mapped_offset, size = self._find_segment(current_offset)
                # If it starts before the current_offset, bring the lower edge up to the right place
                if current_offset > logical_offset:
                    difference = current_offset - logical_offset
                    logical_offset += difference
                    mapped_offset += difference
                    size -= difference
            except exceptions.InvalidAddressException:
                if not ignore_errors:
                    # If we're not ignoring errors, raise the invalid address exception
                    raise
                try:
                    # Find the next valid segment after our current_offset
                    logical_offset, mapped_offset, size = self._find_segment(current_offset, next = True)
                    # We know that the logical_offset must be greater than current_offset so skip to that value
                    current_offset = logical_offset
                    # If it starts too late then we're done
                    if logical_offset > offset + length:
                        raise StopIteration
                except exceptions.InvalidAddressException:
                    raise StopIteration
            # Crop it to the amount we need left
            chunk_size = min(size, length + offset - logical_offset)
            yield (logical_offset, mapped_offset, chunk_size, self._base_layer)
            current_offset += chunk_size
            # Terminate if we've gone (or reached) our required limit
            if current_offset >= offset + length:
                done = True

    @property
    def minimum_address(self) -> int:
        if not self._segments:
            raise ValueError("SegmentedLayer must contain some segments")
        if self._minaddr is None:
            mapped, _, _ = self._segments[0]
            self._minaddr = mapped
        return self._minaddr

    @property
    def maximum_address(self) -> int:
        if not self._segments:
            raise ValueError("SegmentedLayer must contain some segments")
        if self._maxaddr is None:
            mapped, _, length = self._segments[-1]
            self._maxaddr = mapped + length
        return self._maxaddr

    @property
    def dependencies(self) -> typing.List[str]:
        """Returns a list of the lower layers that this layer is dependent upon"""
        return [self._base_layer]

    @classmethod
    def get_requirements(cls) -> typing.List[interfaces.configuration.RequirementInterface]:
        return [requirements.TranslationLayerRequirement(name = 'base_layer',
                                                         optional = False)]
