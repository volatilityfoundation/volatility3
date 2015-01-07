from abc import abstractmethod, ABCMeta
import collections

from volatility.framework import validity


__author__ = 'mike'

Column = collections.namedtuple('Column', ['index', 'name', 'type'])


class Renderer(validity.ValidityRoutines, metaclass = ABCMeta):
    def __init__(self, options):
        """Accepts an options object to configure the renderers"""
        # FIXME: Once the config option objects are in place, put the _type_check in place

    @abstractmethod
    def get_render_options(self):
        """Returns a list of rendering options"""

    @abstractmethod
    def render(self, grid):
        """Takes a grid object and renders it based on the object's preferences"""


class ColumnSortKey(metaclass = ABCMeta):
    @abstractmethod
    def key(self, values):
        """The key function passed as a sort key to the TreeGrid's visit function"""



