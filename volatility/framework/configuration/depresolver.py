import volatility.framework as framework
import volatility.framework.interfaces as interfaces
import volatility.framework.validity as validity


class DataLayerDependencyResolver(validity.ValidityRoutines):
    def __init__(self):
        # Maintain a cache of translation layers
        self.layer_cache = []
        for layer_class in framework.class_subclasses(interfaces.layers.DataLayerInterface):
            # TODO: Improve this hard coded list with a way for layers to say they're abstract or not
            if layer_class.__name__.endswith("Interface"):
                self.layer_cache.append(layer_class)

    def resolve_dependencies(self, configurable):
        """Takes a configurable and produces a priority ordered tree of possible solutions to satisfy the various requirements

           The return should include each of the potential nodes (and requirements, including optional ones) allowing the UI
           to decide the layer build-path and get all the necessary variables from the user for that path.
        """
        self._check_type(configurable, interfaces.configuration.Configurable)

        for requirement in configurable.get_schemas():
            # If the requirement is a layer/configurable
            # Recurse over it
            print(requirement)
            # Add all base-type requirements
            # Add all optional base-type requirements in order
