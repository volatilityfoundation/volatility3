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

import struct
from typing import Optional, Tuple

from volatility.framework import exceptions, interfaces, validity
from volatility.framework.layers import segmented


class LimeFormatException(exceptions.LayerException):
    """Thrown when an error occurs with the underlying Lime file format"""


class LimeLayer(segmented.SegmentedLayer):
    """A Lime format TranslationLayer. Lime is generally used to store
    physical memory images where there are large holes in the physical
    address space"""

    priority = 21

    MAGIC = 0x4c694d45
    VERSION = 1

    # Magic[4], Version[4], Start[8], End[8], Reserved[8]
    # XXX move this to a custom SymbolSpace?
    _header_struct = struct.Struct('<IIQQQ')

    def __init__(self, context: interfaces.context.ContextInterface, config_path: str, name: str) -> None:
        super().__init__(context, config_path, name)

        # We must run this on creation in order to get the right min/maxaddr in case scanning is our first action
        self._load_segments()

    def _load_segments(self) -> None:
        base_layer = self._context.memory[self._base_layer]
        base_maxaddr = base_layer.maximum_address
        maxaddr = 0
        offset = 0
        header_size = self._header_struct.size
        segments = []

        while offset < base_maxaddr:
            start, end = self._check_header(base_layer, offset)

            if start < maxaddr or end < start:
                raise LimeFormatException("bad start/end 0x{:x}/0x{:x} at file offset 0x{:x}".format(
                    start, end, offset))

            segment_length = end - start + 1
            segments.append((start, offset + header_size, segment_length))
            maxaddr = end
            offset = offset + header_size + segment_length

        if len(segments) == 0:
            raise LimeFormatException("No LiME segments defined in {}".format(self._base_layer))

        self._segments = segments

    @classmethod
    def _check_header(cls, base_layer: interfaces.layers.DataLayerInterface, offset: int = 0) -> Tuple[int, int]:
        try:
            header_data = base_layer.read(offset, cls._header_struct.size)
        except exceptions.InvalidAddressException:
            raise LimeFormatException("Offset 0x{:0x} does not exist within the base layer".format(offset))
        (magic, version, start, end, reserved) = cls._header_struct.unpack(header_data)
        if magic != cls.MAGIC:
            raise LimeFormatException("bad magic 0x{:x} at file offset 0x{:x}".format(magic, offset))
        if version != cls.VERSION:
            raise LimeFormatException("unexpected version {:d} at file offset 0x{:x}".format(version, offset))
        return start, end


class LimeStacker(interfaces.automagic.StackerLayerInterface):
    stack_order = 10

    @classmethod
    def stack(cls,
              context: interfaces.context.ContextInterface,
              layer_name: str,
              progress_callback: validity.ProgressCallback = None) \
            -> Optional[interfaces.layers.DataLayerInterface]:
        try:
            LimeLayer._check_header(context.memory[layer_name])
        except LimeFormatException:
            return None
        new_name = context.memory.free_layer_name("LimeLayer")
        context.config[interfaces.configuration.path_join(new_name, "base_layer")] = layer_name
        return LimeLayer(context, new_name, new_name)
