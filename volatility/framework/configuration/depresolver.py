import volatility.framework as framework
import volatility.framework.validity as validity
from volatility.framework.interfaces import layers, configuration


class DataLayerDependencyResolver(validity.ValidityRoutines):
    def __init__(self):
        # Maintain a cache of translation layers
        self.layer_cache = []
        self.metadata = {}
        self.populate_metadata()

    def populate_metadata(self):
        self.metadata = {}
        for layer_class in framework.class_subclasses(layers.DataLayerInterface):
            for k, v in layer_class.metadata.items():
                if not isinstance(v, list):
                    new_v = self.metadata.get(k, set())
                    new_v.add(v)
                else:
                    new_v = self.metadata.get(k, set()) + v
                self.metadata[k] = new_v
                self.layer_cache.append(layer_class)

    def satisfies(self, layer_class, requirement):
        """Takes the requirement (which should always be a TranslationLayerRequirement) and determines if the
           layer_class satisfies it"""
        satisfied = True
        for k, v in requirement.constraints.items():
            if k in layer_class.metadata:
                if isinstance(v, list):
                    satisfied = satisfied and layer_class.metadata[k] not in v
                else:
                    satisfied = satisfied and (layer_class.metadata[k] == v)
        return satisfied

    def resolve_dependencies(self, configurable):
        """Takes a configurable class and produces a priority ordered tree of possible solutions to satisfy the various requirements

           The return should include each of the potential nodes (and requirements, including optional ones) allowing the UI
           to decide the layer build-path and get all the necessary variables from the user for that path.
        """
        self._check_class(configurable, configuration.Configurable)

        fulfillment = {}

        for requirement in configurable.get_schema():
            # If the requirement is a layer/configurable
            if isinstance(requirement, framework.configuration.TranslationLayerRequirement):
                # Find all the different ways to fulfill it (recursively)
                # TODO: Ensure no cycles or loops
                possibilities = Possibility()
                for potential_layer in self.layer_cache:
                    if self.satisfies(potential_layer, requirement):
                        possibility = self.resolve_dependencies(potential_layer)
                        # Only add a possibility if there are suitable lower layers for it
                        if possibility:
                            possibilities[potential_layer] = possibility
                fulfillment[requirement.name] = possibilities
            else:
                # Add all base-type requirements
                # Add all optional base-type requirements in order
                fulfillment[requirement.name] = requirement
        return fulfillment


class Possibility(dict):
    """Class to differentiate between different available options for completion of a requirement"""
    pass
