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

    def validate_dependencies(self, deptree, context, path = None):
        """Takes a dependency tree and attempts to resolve the tree by validating each branch and using the first that successfully validates

            @param path: A list of path components to access the deptree's configuration details
        """
        # TODO: Simplify config system access to ensure easier code
        # TODO: Improve logging/output of this code to diagnose errors
        if path is None:
            path = []
        for node in deptree:
            if isinstance(node, Node) and not node.requirement.optional:
                for branch, subtree in node.branches.items():
                    if self.validate_dependencies(subtree, context, path = path + [node.requirement.name]):
                        # Generate a layer name
                        layer_name = node.requirement.name
                        counter = 2
                        while layer_name in context.memory:
                            layer_name = node.requirement.name + str(counter)
                            counter += 1

                        # Construct the layer
                        requirement_dict = dict([(n.requirement.name, context.config.get(
                                configuration.schema_name_join(path + [node.requirement.name, n.requirement.name]))) for
                                                 n
                                                 in subtree])
                        context.add_layer(branch(context, layer_name, **requirement_dict))
                        context.config[configuration.schema_name_join(path + [node.requirement.name])] = layer_name
                        break
                else:
                    return False
            try:
                print("NODE", node, "OPTIONAL", node.requirement.optional)
                value = context.config[configuration.schema_name_join(path + [node.requirement.name])]
                print("TEST", value)
                node.requirement.validate(value, context)
            except BaseException as e:
                if not node.requirement.optional:
                    return False
        return True

    def build_tree(self, configurable, path = None):
        """Takes a configurable class and produces a priority ordered tree of possible solutions to satisfy the various requirements

           @param configurable: A Configurable type that requires its dependency tree constructing
           @param path: A list of path components indicating where the configurable resides in the config namespace
           @return deptree: The returned tree should include each of the potential nodes (and requirements, including optional ones) allowing the UI
           to decide the layer build-path and get all the necessary variables from the user for that path.
        """
        self._check_class(configurable, configuration.Configurable)

        if path is None:
            path = []
        deptree = []
        deptree_names = set()

        for requirement in configurable.get_schema():

            # Choose a name for the node/leaf
            node_name = requirement.name
            if node_name in deptree_names:
                node_name += str(len([x for x in deptree_names if x.startswith(requirement.name)]))
            node_path = path + [node_name]

            # If the requirement is a layer/configurable
            if isinstance(requirement, framework.configuration.TranslationLayerRequirement):
                # Find all the different ways to fulfill it (recursively)
                # TODO: Ensure no cycles or loops
                branches = {}
                for potential_layer in self.layer_cache:
                    if self.satisfies(potential_layer, requirement):
                        branch = self.build_tree(potential_layer, path = node_path)
                        # Only add a possibility if there are suitable lower layers for it
                        if branch:
                            branches[potential_layer] = branch
                deptree.append(Node(node_path, requirement = requirement, branches = branches))
            else:
                # Add all base-type requirements
                # Add all optional base-type requirements in order
                deptree.append(Leaf(node_path, requirement))
        return deptree


class Leaf(object):
    def __init__(self, path, requirement = None):
        self.requirement = requirement
        self._path = path

    @property
    def path(self):
        """Returns the string version of the path components for this node"""
        return configuration.schema_name_join(self._path)

    def __repr__(self):
        return "<Leaf: " + self.path + " " + repr(self.requirement) + ">"


class Node(Leaf):
    def __init__(self, path, requirement = None, branches = None):
        Leaf.__init__(self, path, requirement)
        self.branches = branches
        if branches is None:
            self.branches = {}

    def __repr__(self):
        return "<Node: " + self.path + " " + repr(self.branches) + ">"
