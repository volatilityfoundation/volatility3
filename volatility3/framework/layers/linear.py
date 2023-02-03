# This file is Copyright 2022 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

import functools
from typing import List, Optional, Tuple, Iterable

from volatility3.framework import exceptions, interfaces


class LinearlyMappedLayer(interfaces.layers.TranslationLayerInterface):
    """Class to differentiate Linearly Mapped layers (where a => b implies that
    a + c => b + c)"""

    ### Translation layer convenience function

    def translate(
        self, offset: int, ignore_errors: bool = False
    ) -> Tuple[Optional[int], Optional[str]]:
        mapping = list(self.mapping(offset, 0, ignore_errors))
        if len(mapping) == 1:
            original_offset, _, mapped_offset, _, layer = mapping[0]
            if original_offset != offset:
                raise exceptions.LayerException(
                    self.name, f"Layer {self.name} claims to map linearly but does not"
                )
        else:
            if ignore_errors:
                # We should only hit this if we ignored errors, but check anyway
                return None, None
            raise exceptions.InvalidAddressException(
                self.name, offset, f"Cannot translate {offset} in layer {self.name}"
            )
        return mapped_offset, layer

    # ## Read/Write functions for mapped pages
    # Redefine read here for speed reasons (so we don't call a processing method

    @functools.lru_cache(maxsize=512)
    def read(self, offset: int, length: int, pad: bool = False) -> bytes:
        """Reads an offset for length bytes and returns 'bytes' (not 'str') of
        length size."""
        current_offset = offset
        output: List[bytes] = []
        for offset, _, mapped_offset, mapped_length, layer in self.mapping(
            offset, length, ignore_errors=pad
        ):
            if not pad and offset > current_offset:
                raise exceptions.InvalidAddressException(
                    self.name,
                    current_offset,
                    f"Layer {self.name} cannot map offset: {current_offset}",
                )
            elif offset > current_offset:
                output += [b"\x00" * (offset - current_offset)]
                current_offset = offset
            elif offset < current_offset:
                raise exceptions.LayerException(
                    self.name, "Mapping returned an overlapping element"
                )
            if mapped_length > 0:
                output += [
                    self._context.layers.read(layer, mapped_offset, mapped_length, pad)
                ]
            current_offset += mapped_length
        recovered_data = b"".join(output)
        return recovered_data + b"\x00" * (length - len(recovered_data))

    def write(self, offset: int, value: bytes) -> None:
        """Writes a value at offset, distributing the writing across any
        underlying mapping."""
        current_offset = offset
        length = len(value)
        for offset, _, mapped_offset, length, layer in self.mapping(offset, length):
            if offset > current_offset:
                raise exceptions.InvalidAddressException(
                    self.name,
                    current_offset,
                    f"Layer {self.name} cannot map offset: {current_offset}",
                )
            elif offset < current_offset:
                raise exceptions.LayerException(
                    self.name, "Mapping returned an overlapping element"
                )
            self._context.layers.write(layer, mapped_offset, value[:length])
            value = value[length:]
            current_offset += length

    def _scan_iterator(
        self,
        scanner: "interfaces.layers.ScannerInterface",
        sections: Iterable[Tuple[int, int]],
        linear: bool = True,
    ) -> Iterable[interfaces.layers.IteratorValue]:
        return super()._scan_iterator(scanner, sections, linear)
