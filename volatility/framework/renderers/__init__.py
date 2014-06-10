import collections

__author__ = 'mike'

import re

from volatility.framework import validity


class TreeRow(validity.ValidityRoutines):
    """Class providing the interface for an individual Row of the TreeGrid"""

    def __init__(self, treegrid, values):
        self.type_check(treegrid, TreeGrid)
        if not isinstance(self, TreeGrid):
            self.type_check(values, list)
            treegrid.validate_values(values)
        self._treegrid = treegrid
        self._children = []
        self._values = values

    def add_child(self, child):
        """Appends a child to the current Row"""
        self.type_check(child, TreeRow)
        self._children += [child]

    def insert_child(self, child, position):
        """Inserts a child at a specific position in the current Row"""
        self.type_check(child, TreeRow)
        self._children = self._children[:position] + [child] + self._children[:position]

    def clear(self):
        """Removes all children from this row

        :rtype : None
        """
        self._children = []

    @property
    def values(self):
        return self._values

    @property
    def children(self):
        """Returns an iterator of the children of the current row

        :rtype : iterator of TreeRows
        """
        for child in self._children:
            yield child

    def iterator(self, level = 0):
        """Returns an iterator of all rows with their depths

        :type level: int
        :param level: Indicates the depth of the current iterator
        """
        yield (level, self)
        for child in self.children:
            for grandchild in child.iterator(level + 1):
                yield grandchild


Column = collections.namedtuple('Column', ['index', 'name', 'type', 'format'])


class TreeGrid(TreeRow):
    """Class providing the interface for a TreeGrid (which contains TreeRows)"""

    simple_types = set((int, str, float, bytes))

    def __init__(self, columns):
        """Constructs a TreeGrid object using a specific set of columns

        The TreeGrid itself is a root element, that can have children but no values.
        The format_hint is a suggestion to the renderer as to how the field should be portrayed as a string,
        but it should be noted that the renderer is not under obligation to use it.

        :param columns: A list of column tuples made up of (name, type and format_hint).
        """
        self.type_check(columns, list)
        converted_columns = []
        for (name, column_type, column_format) in columns:
            is_simple_type = False
            for stype in self.simple_types:
                is_simple_type = is_simple_type or issubclass(column_type, stype)
            if not is_simple_type:
                raise TypeError("Column " + name + "'s type " + column_type.__class__.__name__ +
                                " is not a simple type")
            if isinstance(column_format, str):
                column_format = FormatSpecification.from_specification(column_format)
            if not (column_format is None or isinstance(column_format, FormatSpecification)):
                raise TypeError(
                    "Column " + name + "'s format " + repr(column_format) + " is not an accepted formatter.")
            converted_columns.append(Column(len(converted_columns), name, column_type, column_format))
        self._columns = converted_columns

        # We can use the special type None because we're the top level node without values
        TreeRow.__init__(self, self, None)

    @property
    def columns(self):
        """Returns list of tuples of (name, type and format_hint)"""
        for column in self._columns:
            yield column

    def validate_values(self, values):
        """Takes a list of values and verified them against the column types"""
        if len(values) != len(self._columns):
            raise ValueError("The length of the values provided does not match the number of columns.")
        for column in self._columns:
            if not isinstance(values[column.index], column.type):
                raise TypeError("Column type " + str(column.index) + " is incorrect.")

    def iterator(self, level = 0):
        """Returns an iterator of all rows with their depths

        :type level: int
        :param level: Indicates the depth of the current iterator
        """
        for child in self.children:
            for grandchild in child.iterator(level + 1):
                yield grandchild


class FormatSpecification(object):
    valid_types = "bcdeEfFgGnosxX%"
    pattern = re.compile("^((?P<fill>.)?(?P<align>[<>=^]))?" +
                         "(?P<sign>[ +-])?" +
                         "(?P<alt>#)?" +
                         "?(?P<zero>0)?" +
                         "(?P<width>[0-9]+)?" +
                         "(?P<precision>[.][0-9]+)?" +
                         "(?P<type>[" + valid_types + "])?$")

    # noinspection PyShadowingBuiltins
    def __init__(self, fill = None, align = None, sign = None, alt = None, zero = None, width = None,
                 precision = None, type = None):  # pylint: disable=W0622
        self._fill = fill
        self._align = align
        self._sign = sign
        self._alt = alt
        self._zero = zero
        self._width = width
        self._precision = precision
        self._type = type

    @classmethod
    def from_specification(cls, format_spec):
        """Converts a format_specification string into a FormatSpecification object

        :param format_spec: Format specification string
        :type format_spec: str

        :rtype: FormatSpecification
        :return: A FormatSpecification object with the various parameters parsed
        """
        result = cls.pattern.match(format_spec)
        if not result:
            raise ValueError("Invalid format specification identified.")
        return cls(result.group('fill'),
                   result.group('align'),
                   result.group('sign'),
                   bool(result.group('alt')),
                   bool(result.group('zero')),
                   int(result.group('width')) if result.group('width') else None,
                   int(result.group('precision')[1:]) if result.group('precision') else None,
                   result.group('type'))

    @property
    def fill(self):
        """Selects a character to fill out the empty space after a specific alignment has been chosen."""
        return self._fill

    @property
    def align(self):
        """Determines how to align the text

        '>' will align to the right (default for numbers)
        '<' will align to the left (default for strings)
        '^' will align to the center
        '=' is only valid for numeric types and will force the padding to go after the sign but before digits

        The alignment option has no meaning if the width is not specified, as it will default to the same width as the
        data.
        """
        return self._align

    @property
    def sign(self):
        """Determines whether to insert a sign

        '+' indicates a sign should be present on both positive and negative numbers
        '-' indicates that a sign should be present only on negative numbers (the default)
        ' ' indicates that a leading space should be used on positive numbers, and a minus sign on negative ones
        """
        return self._sign

    @property
    def alt(self):
        """Specifies whether an alternate form should be used.

        This option is only valid for integer, float, complex and Decimal types. For integers, when binary, octal, or
        hexadecimal output is used, this option adds the prefix respective '0b', '0o', or '0x' to the output value. For
        floats, complex and Decimal the alternate form causes the result of the conversion to always contain a
        decimal-point character, even if no digits follow it. Normally, a decimal-point character appears in the result
        of these conversions only if a digit follows it. In addition, for 'g' and 'G' conversions, trailing zeros are
        not removed from the result.
        """
        return self._alt

    @property
    def zero(self):
        """Specifies whether to enable sign-aware zero-padding for numeric types.

        This is equivalent to a fill character of '0' with an alignment type of '='.
        """
        return self._zero

    @property
    def width(self):
        """Specifies a decimal integer defining the minimum field width.

        If not specified, then the field width will be determined by the content.
        """
        return self._width

    @property
    def precision(self):
        """Specifies a decimal number indicating how many digits after the decimal point should be displayed.

        This specifies a decimal number indicating how many digits should be displayed after the decimal point for a
        floating point value formatted with 'f' and 'F', or before and after the decimal point for a floating point
        value formatted with 'g' or 'G'. For non-number types the field indicates the maximum field size - in other
        words, how many characters will be used from the field content. The precision is not allowed for integer values.
        """
        return self._precision

    @property
    def type(self):
        """Specifies the type conversion

        For complete documentation, see the Format Specification Mini-Language in the python string documentation.
        """
        return self._type

    @fill.setter
    def fill(self, value):
        if value and not (isinstance(value, str) and len(value) == 1):
            raise ValueError("Fill value must be a single character string.")
        self._fill = value or None

    @align.setter
    def align(self, value):
        if value and not (value in "<>^=" and len(value) == 1):
            raise ValueError("Alignment value must be one of '<', '>', '=' or '^', not '" + value + "'.")
        self._align = value or None

    @sign.setter
    def sign(self, value):
        if value and not (value in "" and len(value) == 1):
            raise ValueError("Sign value must be one of '-', '+' or ' ', not '" + value + "'.")
        self._sign = value or None

    @alt.setter
    def alt(self, value):
        self._alt = bool(value)

    @zero.setter
    def zero(self, value):
        self._zero = bool(value)

    @width.setter
    def width(self, value):
        self._width = int(value)

    @precision.setter
    def precision(self, value):
        self._precision = int(value)

    @type.setter
    def type(self, value):
        if not (value in self.valid_types and len(value) == 1):
            raise ValueError("Invalid type value provided.")
        self._type = value

    def to_string(self):
        return str(self)

    def __str__(self):
        """"""
        spec = ((self.fill if self.fill and self.align else '') +
                (self.align or '') +
                (self.sign or '') +
                ('#' if self.alt else '') +
                ('0' if self.zero else '') +
                (str(self.width) if self.width else '') +
                (("." + str(self.precision)) if self.precision or self.precision == 0 else '') +
                (self.type or ''))
        return spec
