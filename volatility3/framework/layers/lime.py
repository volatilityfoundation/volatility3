# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

import struct
from typing import Optional, Tuple

from volatility3.framework import exceptions, interfaces, constants
from volatility3.framework.layers import segmented


class LimeFormatException(exceptions.LayerException):
    """Thrown when an error occurs with the underlying Lime file format."""


class LimeLayer(segmented.SegmentedLayer):
    """A Lime format TranslationLayer.

    Lime is generally used to store physical memory images where there
    are large holes in the physical layer
    """

    MAGIC = 0x4C694D45
    VERSION = 1

    # Magic[4], Version[4], Start[8], End[8], Reserved[8]
    # XXX move this to a custom SymbolSpace?
    _header_struct = struct.Struct("<IIQQQ")

    def __init__(
        self, context: interfaces.context.ContextInterface, config_path: str, name: str
    ) -> None:
        super().__init__(context, config_path, name)

        # The base class loads the segments on initialization, but otherwise this must to get the right min/max addresses

    def _load_segments(self) -> None:
        base_layer = self._context.layers[self._base_layer]
        base_maxaddr = base_layer.maximum_address
        maxaddr = 0
        offset = 0
        header_size = self._header_struct.size
        segments = []

        while offset < base_maxaddr:
            start, end = self._check_header(base_layer, offset)

            if start < maxaddr or end < start:
                raise LimeFormatException(
                    self.name,
                    f"Bad start/end 0x{start:x}/0x{end:x} at file offset 0x{offset:x}",
                )

            segment_length = end - start + 1
            segments.append(
                (start, offset + header_size, segment_length, segment_length)
            )
            maxaddr = end
            offset = offset + header_size + segment_length

        if len(segments) == 0:
            raise LimeFormatException(
                self.name, f"No LiME segments defined in {self._base_layer}"
            )

        self._segments = segments

    @classmethod
    def _check_header(
        cls, base_layer: interfaces.layers.DataLayerInterface, offset: int = 0
    ) -> Tuple[int, int]:
        try:
            header_data = base_layer.read(offset, cls._header_struct.size)
        except exceptions.InvalidAddressException:
            raise LimeFormatException(
                base_layer.name,
                f"Offset 0x{offset:0x} does not exist within the base layer",
            )
        (magic, version, start, end, reserved) = cls._header_struct.unpack(header_data)
        if magic != cls.MAGIC:
            raise LimeFormatException(
                base_layer.name, f"Bad magic 0x{magic:x} at file offset 0x{offset:x}"
            )
        if version != cls.VERSION:
            raise LimeFormatException(
                base_layer.name,
                f"Unexpected version {version:d} at file offset 0x{offset:x}",
            )
        return start, end


class LimeStacker(interfaces.automagic.StackerLayerInterface):
    stack_order = 10

    @classmethod
    def stack(
        cls,
        context: interfaces.context.ContextInterface,
        layer_name: str,
        progress_callback: constants.ProgressCallback = None,
    ) -> Optional[interfaces.layers.DataLayerInterface]:
        try:
            LimeLayer._check_header(context.layers[layer_name])
        except LimeFormatException:
            return None
        new_name = context.layers.free_layer_name("LimeLayer")
        context.config[
            interfaces.configuration.path_join(new_name, "base_layer")
        ] = layer_name
        return LimeLayer(context, new_name, new_name)
