'''
Created on 1 Mar 2013

@author: mike
'''

import volatility.framework.interfaces as interfaces

class ObjectTemplate(interfaces.Template):
    """Factory class that produces objects that adhere to the Object interface on demand
    
       This is effectively a method of currying, but adds more structure to avoid abuse.
       It also allows inspection of information that should already be known:
       * Structure size
       * Members, etc
       etc.
    """
    def __init__(self, object_class = None, symbol_name = None, **kwargs):
        super(ObjectTemplate, self).__init__(symbol_name = symbol_name, **kwargs)
        if not issubclass(object_class, interfaces.ObjectInterface):
            raise TypeError("ObjectTemplate object_class must inherit from ObjectInterface")
        self.object_class = object_class

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
        self.object_class.replace_child(old_child, new_child, self._kwargs)

    def __call__(self, context, layer_name, offset, parent = None):
        """Constructs the object
        
           Returns: an object adhereing to the Object interface 
        """
        return self.object_class(context = context, layer_name = layer_name, offset = offset, symbol_name = self.symbol_name, size = self.size, parent = parent, **self._kwargs)

class ReferenceTemplate(interfaces.Template):
    """Factory class that produces objects based on a delayed reference type
    
       It should not return any attributes 
    """
    def __call__(self, context, *args, **kwargs):
        template = context.symbol_space.resolve(self._symbol_name)
        return template(context = context, *args, **kwargs)
