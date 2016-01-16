import volatility.framework as framework
import volatility.framework.validity as validity
from volatility.framework.interfaces import configuration


class DependencyResolver(validity.ValidityRoutines):
    def __init__(self):
        # Maintain a cache of translation layers
        self.configurable_cache = []
        self.provides = {}
        self.providers_cache = set(self._build_caches(configuration.ProviderInterface))

    def _build_caches(self, clazz):
        self.provides = {}
        cache = set()
        for provider in framework.class_subclasses(clazz):
            for k, v in provider.provides.items():
                if not isinstance(v, list):
                    new_v = self.provides.get(k, set())
                    new_v.add(v)
                else:
                    new_v = self.provides.get(k, set()).union(set(v))
                self.provides[k] = new_v
                cache.add(provider)
        return cache

    def satisfies(self, provider, requirement):
        """Takes the requirement (which should always be a TranslationLayerRequirement) and determines if the
           layer_class satisfies it"""
        satisfied = True
        for k, v in requirement.constraints.items():
            if k in provider.provides:
                satisfied = satisfied and bool(self.common_provision(provider.provides[k], v))
        return satisfied

    def common_provision(self, value1, value2):
        """Normalizes individual values down to singleton lists, then tests for overlap between the two lists"""
        if not isinstance(value1, list):
            value1 = [value1]
        if not isinstance(value2, list):
            value2 = [value2]
        set1 = set(value1)
        set2 = set(value2)
        return set1.intersection(set2)

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
                for provider in node.candidates:
                    if self.validate_dependencies(node.candidates[provider], context, path = node_path):
                        provider.fulfill(context, node.requirement, node_path)
                        break
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
        """Takes a configurable and produces a priority ordered tree of possible solutions to satisfy the various requirements

           @param configurable: A configurable class that requires its dependency tree constructing
           @param path: A path indicating where the configurable resides in the config namespace
           @return deptree: The returned tree should include each of the potential nodes (and requirements, including optional ones) allowing the UI
           to decide the layer build-path and get all the necessary variables from the user for that path.
        """
        self._check_class(configurable, configuration.ConfigurableInterface)

        deptree = []

        for subreq in configurable.get_schema():
            # Find all the different ways to fulfill it (recursively)
            # TODO: Ensure no cycles or loops
            if not isinstance(subreq, configuration.ConstraintInterface):
                deptree.append(RequirementTreeLeaf(requirement = subreq))
            else:
                candidates = {}
                satisfiable = False
                for potential in self.providers_cache:
                    if self.satisfies(potential, subreq):
                        try:
                            candidate = self.build_tree(potential)
                            candidates[potential] = candidate
                            satisfiable = True
                        except DependencyError:
                            pass
                # Check we've satisfied one of the possibilities, exception if we haven't
                if not satisfiable:
                    raise DependencyError("No solutions to fulfill requirement " + repr(subreq))
                # Construct the appropriate Requirement node
                if candidates:
                    deptree.append(RequirementTreeNode(requirement = subreq, candidates = candidates))
        return deptree


class DependencyError(Exception):
    pass


class RequirementTreeLeaf(validity.ValidityRoutines):
    def __init__(self, requirement = None):
        validity.ValidityRoutines.__init__(self)
        self._check_type(requirement, configuration.RequirementInterface)
        self.requirement = requirement

    def __repr__(self):
        return "<Leaf: " + repr(self.requirement) + ">"


class RequirementTreeNode(RequirementTreeLeaf):
    def __init__(self, requirement = None, candidates = None):
        RequirementTreeLeaf.__init__(self, requirement)
        for k in candidates:
            self._check_class(k, configuration.ProviderInterface)
            for node in candidates[k]:
                self._check_type(node, RequirementTreeLeaf)
        self.candidates = candidates
        if candidates is None:
            self.candidates = {}

    def __repr__(self):
        return "<Node: " + repr(self.requirement) + " Candidates: " + repr(self.candidates) + ">"
