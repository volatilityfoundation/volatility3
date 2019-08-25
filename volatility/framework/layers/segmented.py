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
import functools
from abc import ABCMeta, abstractmethod
from bisect import bisect_right
from typing import Any, Dict, Iterable, List, Optional, Tuple

from volatility.framework import exceptions, interfaces
from volatility.framework.configuration import requirements


class LinearlyMappedLayer(interfaces.layers.TranslationLayerInterface):
    """Class to differentiate Linearly Mapped layers (where a => b implies that a + c => b + c)"""

    ### Translation layer convenience function

    def translate(self, offset: int, ignore_errors: bool = False) -> Tuple[Optional[int], Optional[str]]:
        mapping = list(self.mapping(offset, 0, ignore_errors))
        if len(mapping) == 1:
            original_offset, mapped_offset, _, layer = mapping[0]
            if original_offset != offset:
                raise exceptions.LayerException(self.name,
                                                "Layer {} claims to map linearly but does not".format(self.name))
        else:
            if ignore_errors:
                # We should only hit this if we ignored errors, but check anyway
                return None, None
            raise exceptions.InvalidAddressException(self.name, offset,
                                                     "Cannot translate {} in layer {}".format(offset, self.name))
        return mapped_offset, layer

    # ## Read/Write functions for mapped pages
    # Redefine read here for speed reasons (so we don't call a processing method

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
                raise exceptions.LayerException(self.name, "Mapping returned an overlapping element")
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
                raise exceptions.LayerException(self.name, "Mapping returned an overlapping element")
            self._context.layers.write(layer, mapped_offset, value[:length])
            value = value[length:]
            current_offset += length


class NonLinearlyMappedLayer(interfaces.layers.TranslationLayerInterface):
    """Class to allow layers which don't map linearly to exist"""


class SegmentedLayer(interfaces.layers.TranslationLayerInterface, metaclass = ABCMeta):
    """A class to handle a single run-based layer-to-layer mapping

       In the documentation "mapped address" or "mapped offset" refers to an offset once it has been mapped to the underlying layer
    """

    def __init__(self,
                 context: interfaces.configuration.ContextInterface,
                 config_path: str,
                 name: str,
                 metadata: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(context = context, config_path = config_path, name = name, metadata = metadata)

        self._base_layer = self.config["base_layer"]
        self._segments = []  # type: List[Tuple[int, int, int]]
        self._minaddr = None  # type: Optional[int]
        self._maxaddr = None  # type: Optional[int]

        self._load_segments()

    @abstractmethod
    def _load_segments(self) -> None:
        """Populates the _segments variable

           Segments must be (address, mapped address, length) and must be sorted by address when this method exits
        """

    def is_valid(self, offset: int, length: int = 1) -> bool:
        """Returns whether the address offset can be translated to a valid address"""
        try:
            base_layer = self._context.layers[self._base_layer]
            return all(
                [base_layer.is_valid(mapped_offset) for _i, mapped_offset, _i, _s in self.mapping(offset, length)])
        except exceptions.InvalidAddressException:
            return False

    def _find_segment(self, offset: int, next: bool = False) -> Tuple[int, int, int]:
        """Finds the segment containing a given offset

           Returns the segment tuple (offset, mapped_offset, length)
        """

        if not self._segments:
            self._load_segments()

        # Find rightmost value less than or equal to x
        i = bisect_right(self._segments, (offset, self.context.layers[self._base_layer].maximum_address))
        if i and not next:
            segment = self._segments[i - 1]
            if segment[0] <= offset < segment[0] + segment[2]:
                return segment
        if next:
            if i < len(self._segments):
                return self._segments[i]
        raise exceptions.InvalidAddressException(self.name, offset, "Invalid address at {:0x}".format(offset))

    def mapping(self, offset: int, length: int, ignore_errors: bool = False) -> Iterable[Tuple[int, int, int, str]]:
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
                        return
                except exceptions.InvalidAddressException:
                    return
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
    def dependencies(self) -> List[str]:
        """Returns a list of the lower layers that this layer is dependent upon"""
        return [self._base_layer]

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [requirements.TranslationLayerRequirement(name = 'base_layer', optional = False)]
