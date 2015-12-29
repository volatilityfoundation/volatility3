"""
Created on 1 Mar 2013

@author: mike
"""

from volatility.framework import interfaces, validity


class ObjectTemplate(interfaces.objects.Template, validity.ValidityRoutines):
    """Factory class that produces objects that adhere to the Object interface on demand

       This is effectively a method of currying, but adds more structure to avoid abuse.
       It also allows inspection of information that should already be known:
       * Structure size
       * Members, etc
       etc.
    """

    def __init__(self, object_class = None, structure_name = None, **arguments):
        interfaces.objects.Template.__init__(self,
                                             structure_name = structure_name,
                                             **arguments)
        self._check_class(object_class, interfaces.objects.ObjectInterface)
        self.update_vol(object_class = object_class)

    @property
    def size(self):
        """Returns the size of the template"""
        return self.vol.object_class.VolTemplateProxy.size(self)

    @property
    def children(self):
        """A function that returns a list of child templates of a template

           This is used to traverse the template tree
        """
        return self.vol.object_class.VolTemplateProxy.children(self)

    def relative_child_offset(self, child):
        """A function that returns the relative offset of a child from its parent offset

           This may throw exceptions including ChildNotFoundException and NotImplementedError
        """
        return self.vol.object_class.VolTemplateProxy.relative_child_offset(self, child)

    def replace_child(self, old_child, new_child):
        """A function for replacing one child with another

           We pass in the kwargs directly so they can be changed
        """
        return self.vol.object_class.VolTemplateProxy.replace_child(self, old_child, new_child)

    def __call__(self, context, object_info):
        """Constructs the object

           Returns: an object adhereing to the Object interface
        """
        arguments = {}
        arguments.update(self.vol)
        del arguments['object_class']
        return self.vol.object_class(context = context,
                                     object_info = object_info,
                                     **arguments)


class ReferenceTemplate(interfaces.objects.Template):
    """Factory class that produces objects based on a delayed reference type

       It should not return any attributes
    """

    def __call__(self, context, object_info):
        template = context.symbol_space.get_structure(self.vol.structure_name)
        return template(context = context, object_info = object_info)
