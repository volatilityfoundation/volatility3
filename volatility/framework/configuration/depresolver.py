import logging
from collections import OrderedDict

import volatility.framework as framework
from volatility.framework import validity, interfaces


def satisfies(provider, requirement):
    """Takes the requirement (which should always be a TranslationLayerRequirement) and determines if the
       layer_class satisfies it"""
    satisfied = True
    for k, v in requirement.constraints.items():
        if k in provider.provides:
            satisfied = satisfied and bool(common_provision(provider.provides[k], v))
    return satisfied


def common_provision(value1, value2):
    """Normalizes individual values down to singleton lists, then tests for overlap between the two lists"""
    if not isinstance(value1, list):
        value1 = [value1]
    if not isinstance(value2, list):
        value2 = [value2]
    set1 = set(value1)
    set2 = set(value2)
    return set1.intersection(set2)


class DependencyResolver(validity.ValidityRoutines):
    def __init__(self):
        # Maintain a cache of translation layers
        self.configurable_cache = []
        self.provides = {}
        self.providers_cache = sorted(list(self._build_caches(interfaces.configuration.ProviderInterface)),
                                      key = lambda x: -x.priority)

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

    def validate_dependencies(self, deptree, context, path = None):
        """Takes a dependency tree and attempts to resolve the tree by validating each branch and using the first that successfully validates

            DEPTREE = [ REQUIREMENTS ... ]
            REQUIREMENT = ( NODE | LEAF )
            NODE = req, { candidate : DEPTREE, ... }
            LEAF = req

            @param path: A path to access the deptree's configuration details
        """
        if path is None:
            path = ""

        self._check_type(deptree, interfaces.configuration.RequirementTreeNode)
        visitor = ValidatorVisitor(context)
        deptree.traverse(visitor, path, short_circuit = True)
        return visitor.is_valid()

    def build_tree(self, configurable):
        """Takes a configurable and produces a priority ordered tree of possible solutions to satisfy the various requirements

           @param configurable: A configurable class that requires its dependency tree constructing
           @param path: A path indicating where the configurable resides in the config namespace
           @return deptree: The returned tree should include each of the potential nodes (and requirements, including optional ones) allowing the UI
           to decide the layer build-path and get all the necessary variables from the user for that path.
        """
        self._check_class(configurable, interfaces.configuration.ConfigurableInterface)

        deptree = []

        for subreq in configurable.get_requirements():
            # Find all the different ways to fulfill it (recursively)
            # TODO: Ensure no cycles or loops
            if not isinstance(subreq, interfaces.configuration.ConstraintInterface):
                deptree.append(RequirementTreeReq(requirement = subreq))
            else:
                candidates = OrderedDict()
                satisfiable = False
                for potential in self.providers_cache:
                    if satisfies(potential, subreq):
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
                    deptree.append(RequirementTreeChoice(requirement = subreq, candidates = candidates))
        return RequirementTreeList(deptree)


class DependencyError(Exception):
    pass


##########################
# Visitors
##########################


class ValidatorVisitor(interfaces.configuration.HierachicalVisitor):
    def __init__(self, context):
        self.ctx = context
        self.stack = [(None, [])]

    def is_valid(self):
        _, result_list = self.stack[0]
        return result_list[0]

    def branch_enter(self, node, config_path):
        self.stack.append((node, []))
        return True

    def branch_leave(self, node, config_path):
        (_, child_results), self.stack = self.stack[-1], self.stack[:-1]
        _, stack = self.stack[-1]
        if isinstance(node, RequirementTreeChoice):
            # Don't bother validating if the choice didn't have one success
            if not any(child_results):
                # Choice requirements can still be valid even if their requirements failed if they are optional
                stack.append(node.requirement.optional)
                return True
        else:
            # Don't bother validating if the list failed
            if not all(child_results):
                # List requirements always fail if one inside fails to validate
                # (since optional requirements in the list should validate as true)
                stack.append(False)
                return True
        # If we haven't already determined the result
        if node.requirement is not None:
            return self(node, config_path)
        else:
            stack.append(True)
            return True

    def __call__(self, node, config_path):
        """Returns whether a node is valid"""
        # Determine if we should
        branch_node, branch_results = self.stack[-1]

        if isinstance(branch_node, RequirementTreeChoice) and branch_results and branch_results[-1] == True:
            return False
        if isinstance(branch_node, RequirementTreeList) and branch_results and branch_results[-1] == False:
            return False

        # Attempt to fulfill the provider
        if isinstance(node, RequirementTreeChoice) and not node.requirement.optional:
            # Only try to provide when we're not already sorted
            if self.ctx.config.get(config_path, None) is None:
                for provider in node.candidates:
                    # Recheck the requirements in case the deptree has changed
                    if satisfies(provider, node.requirement):
                        try:
                            provider.fulfill(self.ctx, node.requirement, config_path)
                            break
                        except Exception as e:
                            pass
                else:
                    logging.debug(
                        "Unable to fulfill requirement " + repr(node.requirement) + " - no fulfillable candidates")
                    branch_results.append(False)
                    return True

        try:
            value = self.ctx.config[config_path]
            node.requirement.validate(value, self.ctx)
            branch_results.append(True)
        except Exception as e:
            if not node.requirement.optional:
                logging.debug(
                    "Unable to fulfill non-optional requirement " + repr(node.requirement) + " [" + str(e) + "]")
            branch_results.append(node.requirement.optional)
        return True


class PrettyPrinter(interfaces.configuration.HierachicalVisitor):
    def __init__(self):
        self.lines = []

    def run(self, deptree):
        deptree.traverse(self,
                         config_path = "pprinter",
                         short_circuit = False)
        for line in self.lines:
            print(*line)

    def branch_leave(self, node, config_path):
        return self(node, config_path)

    def __call__(self, node, config_path):
        depth = config_path.count(interfaces.configuration.CONFIG_SEPARATOR)
        lines = [("." * depth, config_path, type(node))]
        if node.requirement is not None:
            lines.append((" " * depth, node.requirement))
        self.lines = lines + self.lines
        return True


##########################
# Requirement tree classes
##########################


class RequirementTreeReq(interfaces.configuration.RequirementTreeNode):
    def __repr__(self):
        return "<Leaf: " + repr(self.requirement) + ">"

    def traverse(self, visitor, config_path = None, short_circuit = False):
        if config_path is None:
            config_path = self.requirement.name
        else:
            self._check_type(config_path, str)
            config_path += interfaces.configuration.CONFIG_SEPARATOR + self.requirement.name

        return visitor(self, config_path)


class RequirementTreeChoice(RequirementTreeReq):
    def __init__(self, requirement = None, candidates = None):
        RequirementTreeReq.__init__(self, requirement)
        for k in candidates:
            self._check_class(k, interfaces.configuration.ProviderInterface)
            self._check_type(candidates[k], RequirementTreeList)
        self.candidates = candidates
        if candidates is None:
            self.candidates = OrderedDict()

    def __repr__(self):
        return "<Choice: " + repr(self.requirement) + " Candidates: " + repr(dict(self.candidates).keys()) + ">"

    def traverse(self, visitor, config_path = None, short_circuit = False):
        if config_path is None:
            config_path = self.requirement.name
        else:
            self._check_type(config_path, str)
            config_path += interfaces.configuration.CONFIG_SEPARATOR + self.requirement.name

        if visitor.branch_enter(self, config_path):
            for node in self.candidates.values():
                cont = node.traverse(visitor, config_path, short_circuit)
                if not cont:
                    break

        return visitor.branch_leave(self, config_path)


class RequirementTreeList(interfaces.configuration.RequirementTreeNode):
    def __init__(self, children = None):
        interfaces.configuration.RequirementTreeNode.__init__(self, None)
        self._check_type(children, list)
        for child in children:
            self._check_type(child, interfaces.configuration.RequirementTreeNode)
        self.children = children

    def __repr__(self):
        return "<List " + hex(self.__hash__()) + ">"

    def traverse(self, visitor, config_path = None, short_circuit = False):
        if config_path is None:
            config_path = ""
        self._check_type(config_path, str)

        if visitor.branch_enter(self, config_path):
            for node in self.children:
                cont = node.traverse(visitor, config_path, short_circuit)
                if not cont:
                    break

        return visitor.branch_leave(self, config_path)
