import datetime
import sys
import typing

from volatility.framework import interfaces, renderers
from volatility.framework.renderers import format_hints


def hex_bytes_as_text(value: bytes) -> str:
    """Renders HexBytes as text"""
    if not isinstance(value, bytes):
        raise TypeError("hex_bytes_as_text takes bytes not: {}".format(type(value)))
    ascii = []
    hex = []
    count = 0
    output = ""
    for byte in value:
        hex.append("{:02x}".format(byte))
        ascii.append(chr(byte) if 0x20 < byte <= 0x7E else ".")
        if (count % 8) == 7:
            output += " ".join(hex[count - 7: count])
            output += "\t"
            output += "".join(ascii[count - 7: count])
            output += "\n"
        count += 1
    return output


class Optional(object):
    def __init__(self, func: typing.Callable[[typing.Any], str]) -> None:
        self._func = func

    def __call__(self, x: typing.Any) -> str:
        if isinstance(x, interfaces.renderers.BaseAbsentValue):
            if isinstance(x, renderers.NotApplicableValue):
                return "N/A"
            else:
                return "-"
        return self._func(x)


class QuickTextRenderer(interfaces.renderers.Renderer):
    type_renderers = {format_hints.Bin: Optional(lambda x: "0b{:b}".format(x)),
                      format_hints.Hex: Optional(lambda x: "0x{:x}".format(x)),
                      format_hints.HexBytes: Optional(hex_bytes_as_text),
                      bytes: Optional(lambda x: x.decode("utf-8")),
                      datetime.datetime: Optional(lambda x: x.strftime("%Y-%m-%d %H:%M:%S.%f %Z")),
                      'default': Optional(lambda x: "{}".format(x))}

    def __init__(self, options = None) -> None:
        super().__init__(options)

    def get_render_options(self):
        pass

    def render(self, grid: interfaces.renderers.TreeGrid) -> None:
        # TODO: Docstrings
        # TODO: Improve text output
        outfd = sys.stdout

        for column in grid.columns:
            # Ignore the type because namedtuples don't realize they have accessible attributes
            outfd.write("\t{}".format(column.name))  # type: ignore
        outfd.write("\n")

        def visitor(node, accumulator):
            accumulator.write("\n")
            for column in grid.columns:
                renderer = self.type_renderers.get(column.type, self.type_renderers['default'])
                accumulator.write("\t" + renderer(node.values[column.index]))
            return accumulator

        grid.populate(visitor, outfd)

        outfd.write("\n")
