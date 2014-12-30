"""
Created on 4 May 2013

@author: mike
"""

from volatility.framework import validity, interfaces, exceptions
from volatility.framework.layers import physical, intel


class Memory(validity.ValidityRoutines):
    """Container for multiple layers of data"""

    def __init__(self):
        self._layers = {}

    def read(self, layer, offset, length, pad = False):
        """Reads from a particular layer at offset for length bytes

           Returns 'bytes' not 'str'
        """
        return self[layer].read(offset, length, pad)

    def write(self, layer, offset, data):
        """Writes to a particular layer at offset for length bytes"""
        self[layer].write(offset, data)

    def add_layer(self, layer):
        """Adds a layer to memory model

           This will throw an exception if the required dependencies are not met
        """
        self._type_check(layer, interfaces.layers.DataLayerInterface)
        if isinstance(layer, interfaces.layers.TranslationLayerInterface):
            if layer.name in self._layers:
                raise exceptions.LayerException("Layer " + layer.name + " already exists.")
            missing_list = [sublayer for sublayer in layer.dependencies if sublayer not in self._layers]
            if missing_list:
                raise exceptions.LayerException("Layer " + layer.name +
                                                " has unmet dependencies of " + ", ".join(missing_list + "."))
        self._layers[layer.name] = layer

    def del_layer(self, name):
        """Removes the layer called name

           This will throw an exception if other layers depend upon this layer
        """
        for layer in self._layers:
            depend_list = [superlayer for superlayer in self._layers if name in superlayer.dependencies]
            if depend_list:
                raise exceptions.LayerException("Layer " + layer.name +
                                                " is depended upon by " + ", ".join(depend_list))
        del self._layers[name]

    def __getitem__(self, name):
        """Returns the layer of specified name"""
        return self._layers[name]

    def check_cycles(self):
        """Runs through the available layers and identifies if there are cycles in the DAG"""
        # TODO: Is having a cycle check necessary?
