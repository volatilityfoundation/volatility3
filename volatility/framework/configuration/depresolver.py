import volatility.framework as framework
import volatility.framework.validity as validity
from volatility.framework.interfaces import layers, configuration
from volatility.framework.interfaces.configuration import RequirementTreeLeaf, RequirementTreeNode


class DependencyResolver(validity.ValidityRoutines):
    def __init__(self):
        # Maintain a cache of translation layers
        self.layer_cache = []
        self.symbol_cache = []
        self.provides = {}
        self._build_caches(layers.DataLayerInterface, self.layer_cache)
        # self._build_caches(, self.symbol_cache)

    def _build_caches(self, clazz, cache):
        self.provides = {}
        for provider in framework.class_subclasses(clazz):
            for k, v in provider.provides.items():
                if not isinstance(v, list):
                    new_v = self.provides.get(k, set())
                    new_v.add(v)
                else:
                    new_v = self.provides.get(k, set()).union(set(v))
                self.provides[k] = new_v
                cache.append(provider)

    def satisfies(self, provider, requirement):
        """Takes the requirement (which should always be a TranslationLayerRequirement) and determines if the
           layer_class satisfies it"""
        satisfied = True
        for k, v in requirement.constraints.items():
            if k in provider.provides:
                if isinstance(v, list):
                    satisfied = satisfied and provider.provides[k] not in v
                else:
                    satisfied = satisfied and (provider.provides[k] == v)
        return satisfied

    def validate_dependencies(self, deptree, context, path = None):
        """Takes a dependency tree and attempts to resolve the tree by validating each branch and using the first that successfully validates

            @param path: A path to access the deptree's configuration details
        """
        # TODO: Simplify config system access to ensure easier code
        # TODO: Improve logging/output of this code to diagnose errors
        if path is None:
            path = ""
        for node in deptree:
            node_path = path + configuration.CONFIG_SEPARATOR + node.requirement.name
            if isinstance(node, RequirementTreeNode) and not node.requirement.optional:
                node_config = context.config.branch(node_path)
                for provider, subtree in node.branches.items():
                    if self.validate_dependencies(subtree, context, path = node_path):
                        if issubclass(provider, layers.DataLayerInterface):
                            # Generate a layer name
                            layer_name = node.requirement.name
                            counter = 2
                            while layer_name in context.memory:
                                layer_name = node.requirement.name + str(counter)
                                counter += 1

                            # Construct the layer
                            requirement_dict = node_config.data
                            context.add_layer(provider(context, node_path, layer_name, **requirement_dict))
                            context.config[node_path] = layer_name
                            break
                            # elif issubclass(provider, )
                else:
                    return False
            try:
                value = context.config[node_path]
                node.requirement.validate(value, context)
            except BaseException as e:
                if not node.requirement.optional:
                    return False
        return True

    def build_tree(self, configurable):
        """Takes a configurable class and produces a priority ordered tree of possible solutions to satisfy the various requirements

           @param configurable: A Configurable type that requires its dependency tree constructing
           @param path: A path indicating where the configurable resides in the config namespace
           @return deptree: The returned tree should include each of the potential nodes (and requirements, including optional ones) allowing the UI
           to decide the layer build-path and get all the necessary variables from the user for that path.
        """
        self._check_class(configurable, configuration.Configurable)

        deptree = []
        deptree_names = set()

        for requirement in configurable.get_schema():

            # Choose a name for the node/leaf
            node_name = requirement.name
            if node_name in deptree_names:
                node_name += str(len([x for x in deptree_names if x.startswith(requirement.name)]))

            # If the requirement is a layer/configurable
            if isinstance(requirement, framework.configuration.TranslationLayerRequirement):
                # Find all the different ways to fulfill it (recursively)
                # TODO: Ensure no cycles or loops
                branches = {}
                for potential_layer in self.layer_cache:
                    if self.satisfies(potential_layer, requirement):
                        branch = self.build_tree(potential_layer)
                        # Only add a possibility if there are suitable lower layers for it
                        if branch:
                            branches[potential_layer] = branch
                deptree.append(RequirementTreeNode(requirement = requirement, branches = branches))
            elif isinstance(requirement, framework.configuration.SymbolRequirement):
                branches = {}
                for potential_symbol_space in self.symbol_cache:
                    if self.satisfies(potential_symbol_space, requirement):
                        branch = self.build_tree()
            else:
                # Add all base-type requirements
                # Add all optional base-type requirements in order
                deptree.append(RequirementTreeLeaf(requirement))
        return deptree
