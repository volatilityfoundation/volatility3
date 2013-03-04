'''
Created on 1 Mar 2013

@author: mike
'''

import volatility.framework.obj as obj

class ObjectTemplate(object):
    """Factory class that produces objects that adhere to the Object interface on demand
    
       This is effectively a method of currying, but adds more structure to avoid abuse.
       It also allows inspection of information that should already be known:
       * Structure size
       * Members, etc
       etc.
    """
    def __init__(self, objclass, **kwargs):
        self._objclass = objclass
        self._size = None
        self._kwargs = kwargs

    @property
    def size(self):
        return self._size

    def __call__(self, context, symbol_name, offset, layer_name):
        """Constructs the object
        
           Returns: an object adhereing to the Object interface 
        """
        return self._objclass(context, layer_name, offset, symbol_name, self.size, **self._kwargs)

class MemberTemplate(ObjectTemplate):
    """Factory class that produces members of Structs
    
       This is just like a normal ObjectTemplate, but contains the relative offset
       fron the parent object.
    """
    def __init__(self, objclass, relative_offset, **kwargs):
        self._objclass = objclass
        self._reloffset = relative_offset
        self._kwargs = kwargs

    @property
    def relative_offset(self):
        return self._reloffset
