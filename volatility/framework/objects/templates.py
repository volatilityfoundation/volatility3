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
    def __init__(self, object_class = None, symbol_name = None, **kwargs):
        interfaces.objects.Template.__init__(self, symbol_name = symbol_name, **kwargs)
        self.object_class = self.class_check(object_class, interfaces.objects.ObjectInterface)

    @property
    def size(self):
        """Returns the size of the template"""
        return self.object_class.template_size(self._kwargs)

    @property
    def children(self):
        """A function that returns a list of child templates of a template
        
           This is used to traverse the template tree
        """
        return self.object_class.template_children(self._kwargs)

    def replace_child(self, old_child, new_child):
        """A function for replacing one child with another
        
           We pass in the kwargs directly so they can be changed
        """
        self.object_class.template_replace_child(old_child, new_child, self._kwargs)

    def __call__(self, context, layer_name, offset, parent = None):
        """Constructs the object
        
           Returns: an object adhereing to the Object interface 
        """
        # We always use the template size (as calculated by the object class)
        # over the one passed in by an argument
        self._kwargs['size'] = self.size
        self._kwargs['symbol_name'] = self.symbol_name
        return self.object_class(context = context, layer_name = layer_name, offset = offset, parent = parent, **self._kwargs)

class ReferenceTemplate(interfaces.objects.Template):
    """Factory class that produces objects based on a delayed reference type
    
       It should not return any attributes 
    """
    def __call__(self, context, *args, **kwargs):
        template = context.symbol_space.resolve(self._symbol_name)
        return template(context = context, *args, **kwargs)
