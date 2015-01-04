'''
Created on 1 Mar 2013

@author: mike
'''

from volatility.framework import interfaces, validity


class ObjectTemplate(interfaces.objects.Template, validity.ValidityRoutines):
    """Factory class that produces objects that adhere to the Object interface on demand

       This is effectively a method of currying, but adds more structure to avoid abuse.
       It also allows inspection of information that should already be known:
       * Structure size
       * Members, etc
       etc.
    """

    def __init__(self, object_class = None, structure_name = None, **kwargs):
        interfaces.objects.Template.__init__(self,
                                             structure_name = structure_name,
                                             **kwargs)
        self._class_check(object_class, interfaces.objects.ObjectInterface)
        self.update_volinfo(object_class = object_class)

    @classmethod
    def template_children(cls, **kwargs):
        raise NotImplementedError("Abstract method template_children not implemented yet.")

    @classmethod
    def template_size(cls, **kwargs):
        raise NotImplementedError("Abstract method template_size not implemented yet.")

    @property
    def size(self):
        """Returns the size of the template"""
        return self.volinfo.object_class.template_size(self)

    @property
    def children(self):
        """A function that returns a list of child templates of a template

           This is used to traverse the template tree
        """
        return self.volinfo.object_class.template_children(self)

    def relative_child_offset(self, child):
        """A function that returns the relative offset of a child from its parent offset

           This may throw exceptions including ChildNotFoundException and NotImplementedError
        """
        return self.volinfo.object_class.template_relative_child_offset(self, child)

    def replace_child(self, old_child, new_child):
        """A function for replacing one child with another

           We pass in the kwargs directly so they can be changed
        """
        self.volinfo.object_class.template_replace_child(self, old_child, new_child)

    def __call__(self, context, object_info, **kwargs):
        """Constructs the object

           Returns: an object adhereing to the Object interface
        """
        # We always use the template size (as calculated by the object class)
        # over the one passed in by an argument
        return self.volinfo.object_class(context = context,
                                         object_info = object_info,
                                         template_info = self.volinfo,
                                         **kwargs)


class ReferenceTemplate(interfaces.objects.Template):
    """Factory class that produces objects based on a delayed reference type

       It should not return any attributes
    """

    def __call__(self, context, *args, **kwargs):
        template = context.symbol_space.get_structure(self.volinfo.structure_name)
        return template(context = context, *args, **kwargs)
