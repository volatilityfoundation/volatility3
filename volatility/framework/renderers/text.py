import sys

from volatility.framework import interfaces
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


class QuickTextRenderer(interfaces.renderers.Renderer):
    type_renderers = {format_hints.Bin: lambda x: "0b{:b}".format(x),
                      format_hints.Hex: lambda x: "0x{:x}".format(x),
                      format_hints.HexBytes: hex_bytes_as_text,
                      bytes: lambda x: x.decode("utf-8"),
                      'default': lambda x: "{}".format(x)}

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
            for column in grid.columns:
                renderer = self.type_renderers.get(column.type, self.type_renderers['default'])
                accumulator.write("\t" + renderer(node.values[column.index]))
            accumulator.write("\n")
            return accumulator

        grid.populate(visitor, outfd)
