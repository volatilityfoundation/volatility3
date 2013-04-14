'''
Created on 1 Mar 2013

@author: mike
'''

import copy
import volatility.framework.interfaces as interfaces

class ObjectTemplate(object):
    """Factory class that produces objects that adhere to the Object interface on demand
    
       This is effectively a method of currying, but adds more structure to avoid abuse.
       It also allows inspection of information that should already be known:
       * Structure size
       * Members, etc
       etc.
    """
    def __init__(self, object_class = None, symbol_name = None, size = None, **kwargs):
        if not issubclass(object_class, interfaces.ObjectInterface):
            raise TypeError("ObjectTemplate object_class must be a class, not " + str(type(object_class)))
        if not isinstance(size, int):
            raise TypeError("ObjectTemplate size must be numeric, not " + str(type(size)))
        self._size = size
        self._symbol_name = symbol_name
        self._kwargs = kwargs
        self._object_class = object_class

    @property
    def object_class(self):
        return self._object_class

    @property
    def size(self):
        return self._size

    @property
    def symbol_name(self):
        """Returns the name of the symbol if one was provided"""
        return self._symbol_name

    @property
    def kwargs(self):
        return copy.deepcopy(self._kwargs)

    def __call__(self, context, layer_name, offset, parent = None):
        """Constructs the object
        
           Returns: an object adhereing to the Object interface 
        """
        return self._object_class(context = context, layer_name = layer_name, offset = offset, symbol_name = self.symbol_name, size = self.size, parent = parent, **self._kwargs)

def member_from_object_template(relative_offset, object_template):
    """Returns a MemberTemplate based upon an existing ObjectTemplate"""
    if not isinstance(object_template, ObjectTemplate):
        raise TypeError("object_template must be an ObjectTemplate, not " + str(type(object_template)))
    return MemberTemplate(relative_offset = relative_offset,
                          object_class = object_template.object_class,
                          symbol_name = object_template.symbol_name,
                          size = object_template.size,
                          **object_template.kwargs)

class MemberTemplate(ObjectTemplate):
    """Factory class that produces members of Structs
    
       This is just like a normal ObjectTemplate, but contains the relative offset
       fron the parent object.
    """
    def __init__(self, relative_offset, **kwargs):
        super(MemberTemplate, self).__init__(**kwargs)
        if not isinstance(relative_offset, int):
            raise TypeError("MemberTemplate relative_offset must be numeric, not " + str(type(relative_offset)))
        self._relative_offset = relative_offset

    @property
    def relative_offset(self):
        return self._relative_offset
