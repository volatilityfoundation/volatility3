"""
Created on 1 Mar 2013

@author: mike
"""
import logging

from volatility.framework import interfaces, validity
from volatility.framework.exceptions import SymbolError

vollog = logging.getLogger(__name__)


class ObjectTemplate(interfaces.objects.Template, validity.ValidityRoutines):
    """Factory class that produces objects that adhere to the Object interface on demand

       This is effectively a method of currying, but adds more structure to avoid abuse.
       It also allows inspection of information that should already be known:

         * Type size
         * Members
         * etc
    """

    def __init__(self, object_class = None, type_name = None, **arguments):
        super().__init__(type_name = type_name, **arguments)
        self._check_class(object_class, interfaces.objects.ObjectInterface)
        self._arguments['object_class'] = object_class

    @property
    def size(self):
        """Returns the children of the templated object (see :class:`~volatility.framework.interfaces.objects.ObjectInterface.VolTemplateProxy`)"""
        return self.vol.object_class.VolTemplateProxy.size(self)

    @property
    def children(self):
        """Returns the children of the templated object (see :class:`~volatility.framework.interfaces.objects.ObjectInterface.VolTemplateProxy`)
        """
        return self.vol.object_class.VolTemplateProxy.children(self)

    def relative_child_offset(self, child):
        """Returns the relative offset of a child of the templated object (see :class:`~volatility.framework.interfaces.objects.ObjectInterface.VolTemplateProxy`)
        """
        return self.vol.object_class.VolTemplateProxy.relative_child_offset(self, child)

    def replace_child(self, old_child, new_child):
        """Replaces `old_child` for `new_child` in the templated object's child list (see :class:`~volatility.framework.interfaces.objects.ObjectInterface.VolTemplateProxy`)
        """
        return self.vol.object_class.VolTemplateProxy.replace_child(self, old_child, new_child)

    def __call__(self, context, object_info):
        """Constructs the object

           Returns: an object adhereing to the :class:`~volatility.framework.interfaces.objects.ObjectInterface`
        """
        arguments = {}
        arguments.update(self.vol)
        del arguments['object_class']
        return self.vol.object_class(context = context,
                                     object_info = object_info,
                                     **arguments)


class ReferenceTemplate(interfaces.objects.Template):
    """Factory class that produces objects based on a delayed reference type

    Attempts to access any standard attributes of a resolved template will result in a
    :class:`~volatility.framework.exceptions.SymbolError`.
    """

    @property
    def children(self):
        return []

    def _unresolved(self, *args, **kwargs):
        """Referenced symbols must be appropriately resolved before they can provide information such as size
           This is because the size request has no context within which to determine the actual symbol structure.
        """
        raise SymbolError("Template contains no information about its structure: {}".format(self.vol.type_name))

    size = property(_unresolved)
    replace_child = relative_child_offset = _unresolved

    def __call__(self, context, object_info):
        template = context.symbol_space.get_type(self.vol.type_name)
        return template(context = context, object_info = object_info)
