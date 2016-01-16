from volatility.framework.interfaces import configuration as config_interface


class InstanceRequirement(config_interface.RequirementInterface):
    instance_type = bool

    def validate(self, value, _context):
        if not isinstance(value, self.instance_type):
            raise TypeError(self.name + " input only accepts " + self.instance_type.__name__ + " type")


class IntRequirement(InstanceRequirement):
    instance_type = int


class StringRequirement(InstanceRequirement):
    # TODO: Maybe add string length limits?
    instance_type = str


class TranslationLayerRequirement(config_interface.ConstraintInterface):
    """Class maintaining the limitations on what sort of address spaces are acceptable"""

    def __init__(self, name, description = None, default = None,
                 optional = False, layer_name = None, constraints = None):
        """Constructs a Translation Layer Requirement

        The configuration option's value will be the name of the layer once it exists in the store

        :param name: Name of the configuration requirement
        :param layer_name: String detailing the expected name of the required layer, this can be None if it is to be randomly generated
        :return:
        """
        config_interface.ConstraintInterface.__init__(self, name, description, default, optional, constraints)
        self._layer_name = layer_name

    # TODO: Add requirements: acceptable OSes from the address_space information
    # TODO: Add requirements: acceptable arches from the available layers

    def validate(self, value, context):
        """Validate that the value is a valid layer name and that the layer adheres to the requirements"""
        if not isinstance(value, str):
            raise TypeError("TranslationLayerRequirements only accepts string labels")
        if value not in context.memory:
            raise IndexError((value or "") + " is not a memory layer")


class SymbolRequirement(config_interface.ConstraintInterface):
    """Class maintaining the limitations on what sort of symbol spaces are acceptable"""

    def __init__(self, name, description = None, default = None, optional = False, constraints = None):
        config_interface.ConstraintInterface.__init__(self, name, description, default, optional, constraints)

    def validate(self, value, context):
        """Validate that the value is a valid within the symbol space of the provided context"""
        if not isinstance(value, str):
            raise TypeError("SymbolRequirement only accepts string labels")
        if value not in context.symbol_space:
            raise IndexError((value or "") + " is not present in the symbol space")


class ChoiceRequirement(config_interface.RequirementInterface):
    """Allows one from a choice of strings"""

    def __init__(self, choices, *args, **kwargs):
        config_interface.RequirementInterface.__init__(self, *args, **kwargs)
        if not isinstance(choices, list) or any([not isinstance(choice, str) for choice in choices]):
            raise TypeError("ChoiceRequirement takes a list of strings as choices")
        self._choices = choices

    def validate(self, value, context):
        """Validates the provided value to ensure it is one of the available choices"""
        if value not in self._choices:
            raise ValueError("Value is not within the set of available choices")


class ListRequirement(config_interface.RequirementInterface):
    def __init__(self, element_type, max_elements, min_elements, *args, **kwargs):
        config_interface.RequirementInterface.__init__(self, *args, **kwargs)
        if isinstance(element_type, ListRequirement):
            raise TypeError("ListRequirements cannot contain ListRequirements")
        self.element_type = self._check_type(element_type, config_interface.RequirementInterface)
        self.min_elements = min_elements
        self.max_elements = max_elements

    def validate(self, value, context):
        """Check the types on each of the returned values and then call the element type's check for each one"""
        self._check_type(value, list)
        if not all([self._check_type(element, self.element_type) for element in value]):
            raise TypeError("At least one element in the list is not of the correct type.")
        if not (self.min_elements <= len(value) <= self.max_elements):
            raise TypeError("List option provided more or less elements than allowed.")
        for element in value:
            self.element_type.validate(element, context)
