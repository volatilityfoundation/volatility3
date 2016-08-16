import logging

from volatility.framework import interfaces

vollog = logging.getLogger(__name__)


class MultiRequirement(interfaces.configuration.RequirementInterface):
    """Class to hold multiple requirements

       Technically the Interface could handle this, but it's an interface, so this is a concrete implementation
    """

    def validate(self, context, config_path):
        return self.validate_children(context, config_path)


class InstanceRequirement(interfaces.configuration.RequirementInterface):
    instance_type = bool

    def add_requirement(self, requirement):
        raise TypeError("Instance Requirements cannot have subrequirements")

    def remove_requirement(self, requirement):
        raise TypeError("Instance Requirements cannot have subrequirements")

    def validate(self, context, config_path):
        value = self.config_value(context, config_path, None)
        if not isinstance(value, self.instance_type):
            vollog.debug("TypeError - " + self.name + " input only accepts " + self.instance_type.__name__ + " type")
            return False
        return True


class IntRequirement(InstanceRequirement):
    instance_type = int


class StringRequirement(InstanceRequirement):
    # TODO: Maybe add string length limits?
    instance_type = str


class BytesRequirement(InstanceRequirement):
    instance_type = bytes


class TranslationLayerRequirement(interfaces.configuration.ConstructableRequirementInterface):
    """Class maintaining the limitations on what sort of address spaces are acceptable"""

    def __init__(self, name, description = None, default = None, optional = False):
        """Constructs a Translation Layer Requirement

        The configuration option's value will be the name of the layer once it exists in the store

        :param name: Name of the configuration requirement
        :param layer_name: String detailing the expected name of the required layer, this can be None if it is to be randomly generated
        :return:
        """
        super().__init__(name, description, default, optional)

    # TODO: Add requirements: acceptable OSes from the address_space information
    # TODO: Add requirements: acceptable arches from the available layers

    def validate(self, context, config_path):
        """Validate that the value is a valid layer name and that the layer adheres to the requirements"""
        value = self.config_value(context, config_path, None)
        if isinstance(value, str):
            if value not in context.memory:
                vollog.debug("IndexError - Layer " + value + " not found in memory space")
                return False
            return True

        if value is not None:
            vollog.debug("TypeError - TranslationLayerRequirements only accepts string labels")
            return False

        # TODO: check that the space in the context lives up to the requirements for arch/os etc

        ### NOTE: This validate method has side effects (the dependencies can change)!!!

        self._check_class(context, config_path)
        vollog.debug("IndexError - No configuration provided for layer")
        return False

    def construct(self, context, config_path):
        """Constructs the appropriate layer and adds it based on the class parameter"""
        # Determine the layer name
        name = self.name
        counter = 2
        while name in context.memory:
            name = self.name + str(counter)
            counter += 1

        args = {"context": context,
                "config_path": config_path,
                "name": name}

        config_path = interfaces.configuration.path_join(config_path, self.name)
        if not all([subreq.validate(context, config_path) for subreq in self.requirements.values() if
                    not subreq.optional]):
            return False

        obj = self._construct_class(context, config_path, args)
        if obj is None:
            return False
        context.add_layer(obj)
        return True


class SymbolRequirement(interfaces.configuration.ConstructableRequirementInterface):
    """Class maintaining the limitations on what sort of symbol spaces are acceptable"""

    def validate(self, context, config_path):
        """Validate that the value is a valid within the symbol space of the provided context"""
        value = self.config_value(context, config_path, None)
        if not isinstance(value, str):
            vollog.debug("TypeError - SymbolRequirement only accepts string labels")
            return False
        if value not in context.symbol_space:
            # This is an expected situation, so return False rather than raise
            vollog.debug("IndexError - " + (value or "") + " is not present in the symbol space")
            return False
        return True

    def construct(self, context, config_path):
        """Constructs the symbol space within the context based on the subrequirements"""
        # Determine the space name
        name = self.name
        if name in context.symbol_space:
            raise ValueError("Symbol space already contains a SymbolTable by the same name")

        args = {"context": context,
                "config_path": config_path,
                "name": name}

        config_path = interfaces.configuration.path_join(config_path, self.name)
        if not all([subreq.validate(context, config_path) for subreq in self.requirements.values() if
                    not subreq.optional]):
            return False

        obj = self._construct_class(context, config_path, args)
        if obj is None:
            return False
        context.symbol_space.append(obj)
        return True


class ChoiceRequirement(interfaces.configuration.RequirementInterface):
    """Allows one from a choice of strings"""

    def __init__(self, choices, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if not isinstance(choices, list) or any([not isinstance(choice, str) for choice in choices]):
            raise TypeError("ChoiceRequirement takes a list of strings as choices")
        self._choices = choices

    def validate(self, context, config_path):
        """Validates the provided value to ensure it is one of the available choices"""
        value = self.config_value(context, config_path)
        if value not in self._choices:
            vollog.debug("ValueError - Value is not within the set of available choices")
            return False
        return True


class ListRequirement(interfaces.configuration.RequirementInterface):
    def __init__(self, element_type, max_elements, min_elements, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if isinstance(element_type, ListRequirement):
            raise TypeError("ListRequirements cannot contain ListRequirements")
        self.element_type = self._check_type(element_type, interfaces.configuration.RequirementInterface)
        self.min_elements = min_elements
        self.max_elements = max_elements

    def validate(self, context, config_path):
        """Check the types on each of the returned values and then call the element type's check for each one"""
        value = self.config_value(context, config_path)
        self._check_type(value, list)
        if not all([self._check_type(element, self.element_type) for element in value]):
            vollog.debug("TypeError - At least one element in the list is not of the correct type.")
            return False
        if not (self.min_elements <= len(value) <= self.max_elements):
            vollog.debug("TypeError - List option provided more or less elements than allowed.")
            return False
        return all([self.element_type.validate(context, element) for element in value])
