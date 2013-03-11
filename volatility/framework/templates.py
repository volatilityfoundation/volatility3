'''
Created on 1 Mar 2013

@author: mike
'''

class ObjectTemplate(object):
    """Factory class that produces objects that adhere to the Object interface on demand
    
       This is effectively a method of currying, but adds more structure to avoid abuse.
       It also allows inspection of information that should already be known:
       * Structure size
       * Members, etc
       etc.
    """
    def __init__(self, objclass, symbol_name = None, size = None, **kwargs):
        self._objclass = objclass
        if not isinstance(size, int):
            raise TypeError("ObjectTemplate size must be numeric, not " + str(type(size)))
        self._size = size
        self._symbol_name = symbol_name
        self._kwargs = kwargs

    @property
    def size(self):
        return self._size

    @property
    def symbol_name(self):
        """Returns the name of the symbol if one was provided"""
        return self._symbol_name

    def __call__(self, context, offset, layer_name, parent = None):
        """Constructs the object
        
           Returns: an object adhereing to the Object interface 
        """
        return self._objclass(context, layer_name, offset, self.symbol_name, self.size, parent, **self._kwargs)

class MemberTemplate(ObjectTemplate):
    """Factory class that produces members of Structs
    
       This is just like a normal ObjectTemplate, but contains the relative offset
       fron the parent object.
    """
    def __init__(self, objclass, symbol_name = None, size = None, relative_offset = None, *args, **kwargs):
        if not isinstance(relative_offset, int):
            raise TypeError("MemberTemplate relative_offset must be numeric, not " + str(type(relative_offset)))
        self._reloffset = relative_offset
        ObjectTemplate.__init__(self, objclass, symbol_name, size, *args, **kwargs)

    @property
    def relative_offset(self):
        return self._reloffset

