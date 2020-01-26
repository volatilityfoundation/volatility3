import functools
from typing import List, Optional, Tuple, Iterable

from volatility.framework import exceptions, interfaces


class LinearlyMappedLayer(interfaces.layers.TranslationLayerInterface):
    """Class to differentiate Linearly Mapped layers (where a => b implies that
    a + c => b + c)"""

    ### Translation layer convenience function

    def translate(self, offset: int, ignore_errors: bool = False) -> Tuple[Optional[int], Optional[str]]:
        mapping = list(self.mapping(offset, 0, ignore_errors))
        if len(mapping) == 1:
            original_offset, _, mapped_offset, _, layer = mapping[0]
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
        """Reads an offset for length bytes and returns 'bytes' (not 'str') of
        length size."""
        current_offset = offset
        output = []  # type: List[bytes]
        for (offset, _, mapped_offset, mapped_length, layer) in self.mapping(offset, length, ignore_errors = pad):
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
        """Writes a value at offset, distributing the writing across any
        underlying mapping."""
        current_offset = offset
        length = len(value)
        for (offset, _, mapped_offset, length, layer) in self.mapping(offset, length):
            if offset > current_offset:
                raise exceptions.InvalidAddressException(
                    self.name, current_offset, "Layer {} cannot map offset: {}".format(self.name, current_offset))
            elif offset < current_offset:
                raise exceptions.LayerException(self.name, "Mapping returned an overlapping element")
            self._context.layers.write(layer, mapped_offset, value[:length])
            value = value[length:]
            current_offset += length

    def _scan_iterator(self, scanner: 'interfaces.layers.ScannerInterface',
                       sections: Iterable[Tuple[int, int]]) -> Iterable[interfaces.layers.IteratorValue]:
        """Essentially, for paged systems we take a bunch of pages and chunk them up into scanner.page_size or
        as large a chunk as possible (if there are gaps)."""
        for (section_start, section_length) in sections:
            # For each section, split it into scan size chunks
            for chunk_start in range(section_start, section_start + section_length, scanner.chunk_size):
                # Shorten it, if we're at the end of the section
                chunk_length = min(section_start + section_length - chunk_start, scanner.chunk_size + scanner.overlap)

                # Prev offset keeps track of the end of the previous subchunk
                prev_offset = chunk_start
                output = []  # type: List[Tuple[str, int, int]]
                # We populate the response based on subchunks that may be mapped all over the place
                for mapped in self.mapping(chunk_start, chunk_length, ignore_errors = True):
                    offset, _, mapped_offset, mapped_length, layer_name = mapped

                    # We need to check if the offset is next to the end of the last one (contiguous)
                    if offset != prev_offset:
                        # Only yield if we've accumulated output
                        if len(output):
                            # Yield all the (joined) items so far
                            # and the ending point of that subchunk (where we'd gotten to previously)
                            yield output, prev_offset
                        output = []

                    # Shift the marker up to the end of what we just received and add it to the output
                    prev_offset = offset + mapped_length
                    output += [(layer_name, mapped_offset, mapped_length)]
                # If there's still output left, output it
                if len(output):
                    yield output, prev_offset
