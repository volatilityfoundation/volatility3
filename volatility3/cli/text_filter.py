import logging
from typing import Any, List, Optional
from volatility3.framework import constants, interfaces
import re

vollog = logging.getLogger(__name__)


class CLIFilter:
    def __init__(self, treegrid, filters: List[str]):
        self._filters = self._prepare(treegrid, filters)

    def _prepare(self, treegrid: interfaces.renderers.TreeGrid, filters: List[str]):
        """Runs through the filter strings and creates the necessary filter objects"""
        output = []

        for filter in filters:
            exclude = False
            regex = False
            pattern = None
            column_name = None
            if filter.startswith("-"):
                exclude = True
                filter = filter[1:]
            elif filter.startswith("+"):
                filter = filter[1:]
            components = filter.split(",")
            if len(components) < 2:
                pattern = components[0]
            else:
                column_name = components[0]
                pattern = ",".join(components[1:])
            if pattern and pattern.endswith("!"):
                regex = True
                pattern = pattern[:-1]
            column_num = None
            if column_name:
                for num, column in enumerate(treegrid.columns):
                    if column_name.lower() in column.name.lower():
                        column_num = num
                        break
            if pattern:
                output.append(ColumnFilter(column_num, pattern, regex, exclude))

        vollog.log(constants.LOGLEVEL_VVV, "Filters:\n" + repr(output))

        return output

    def filter(
        self,
        row: List[Any],
    ) -> bool:
        """Filters the row based on each of the column_filters"""
        if not self._filters:
            return False
        found = any([column_filter.found(row) for column_filter in self._filters])
        return not found


class ColumnFilter:
    def __init__(
        self,
        column_num: Optional[int],
        pattern: str,
        regex: bool = False,
        exclude: bool = False,
    ) -> None:
        self.column_num = column_num
        self.pattern = pattern
        self.exclude = exclude
        self.regex = regex

    def find(self, item) -> bool:
        """Identifies whether an item is found in the appropriate column"""
        try:
            if self.regex:
                return re.search(self.pattern, f"{item}")
            return self.pattern in f"{item}"
        except IOError:
            return False

    def found(self, row: List[Any]) -> bool:
        """Determines whether a row should be filtered

        If the classes exclude value is false, and the necessary pattern is found, the row is not filtered,
        otherwise it is filtered.
        """
        if self.column_num is None:
            found = any([self.find(x) for x in row])
        else:
            found = self.find(row[self.column_num])
        if self.exclude:
            return not found
        return found

    def __repr__(self) -> str:
        """Returns a display of a column filter"""
        return f"ColumnFilter(column={self.column_num},exclude={self.exclude},regex={self.regex},pattern={self.pattern})"
