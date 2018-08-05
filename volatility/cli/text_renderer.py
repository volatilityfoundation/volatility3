import datetime
import logging
import sys
import typing

from volatility.framework.renderers import format_hints

vollog = logging.getLogger(__name__)

try:
    CAPSTONE_PRESENT = True
    import capstone
except ImportError:
    CAPSTONE_PRESENT = False
    vollog.debug("Disassembly library capstone not found")

from volatility.framework import interfaces, renderers


def hex_bytes_as_text(value: bytes) -> str:
    """Renders HexBytes as text

    Args:
        value: A series of bytes to convert to text

    Returns:
        A text representation of the hexadecimal bytes plus their ascii equivalents, separated by newline characters
    """
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
            output += "\n"
            output += " ".join(hex[count - 7: count])
            output += "\t"
            output += "".join(ascii[count - 7: count])
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


def display_disassembly(disasm: interfaces.renderers.Disassembly) -> str:
    """Renders a disassembly renderer type into string format

    Args:
        disasm: Input disassembly objects

    Returns:
        A string as rendererd by capstone where available, otherwise output as if it were just bytes

    """

    if CAPSTONE_PRESENT:
        disasm_types = {'intel': capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32),
                        'intel64': capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64),
                        'arm': capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM),
                        'arm64': capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)}
        output = ""
        if disasm.architecture is not None:
            for i in disasm_types[disasm.architecture].disasm(disasm.data, disasm.offset):
                output += "\n0x%x:\t%s\t%s" % (i.address, i.mnemonic, i.op_str)
        return output
    return QuickTextRenderer.type_renderers[bytes](disasm.data)


class QuickTextRenderer(interfaces.renderers.Renderer):
    type_renderers = {format_hints.Bin: Optional(lambda x: "0b{:b}".format(x)),
                      format_hints.Hex: Optional(lambda x: "0x{:x}".format(x)),
                      format_hints.HexBytes: Optional(hex_bytes_as_text),
                      interfaces.renderers.Disassembly: Optional(display_disassembly),
                      bytes: Optional(lambda x: " ".join(["{0:2x}".format(b) for b in x])),
                      datetime.datetime: Optional(lambda x: x.strftime("%Y-%m-%d %H:%M:%S.%f %Z")),
                      'default': Optional(lambda x: "{}".format(x))}

    def __init__(self, options = None) -> None:
        super().__init__(options)

    def get_render_options(self):
        pass

    def render(self, grid: interfaces.renderers.TreeGrid) -> None:
        """
        Renders each column immediately to stdout.

        This does not format each line's width appropriately, it merely tab separates each field

        Args:
            grid: The TreeGrid object to render

        """
        # TODO: Docstrings
        # TODO: Improve text output
        outfd = sys.stdout

        for column in grid.columns:
            # Ignore the type because namedtuples don't realize they have accessible attributes
            outfd.write("\t{}".format(column.name))  # type: ignore
        outfd.write("\n")

        def visitor(node, accumulator):
            accumulator.write("\n")
            # Nodes always have a path value, giving them a path_depth of at least 1, we use max just in case
            accumulator.write("*" * max(0, node.path_depth - 1))
            for column in grid.columns:
                renderer = self.type_renderers.get(column.type, self.type_renderers['default'])
                accumulator.write("\t" + renderer(node.values[column.index]))
            return accumulator

        grid.populate(visitor, outfd)

        outfd.write("\n")
