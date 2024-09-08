# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
"""Contains standard Requirement types that all adhere to the :class:`~volatili
ty.framework.interfaces.configuration.RequirementInterface`.

These requirement types allow plugins to request simple information
types (such as strings, integers, etc) as well as indicating what they
expect to be in the context (such as particular layers or symboltables).
"""
import abc
import logging
import os
from typing import Any, ClassVar, Dict, List, Optional, Tuple, Type
from urllib import parse, request

from volatility3.framework import constants, interfaces

vollog = logging.getLogger(__name__)


class MultiRequirement(interfaces.configuration.RequirementInterface):
    """Class to hold multiple requirements.

    Technically the Interface could handle this, but it's an interface,
    so this is a concrete implementation.
    """

    def unsatisfied(
        self, context: interfaces.context.ContextInterface, config_path: str
    ) -> Dict[str, interfaces.configuration.RequirementInterface]:
        return self.unsatisfied_children(context, config_path)


class BooleanRequirement(interfaces.configuration.SimpleTypeRequirement):
    """A requirement type that contains a boolean value."""

    # Note, this must be a separate class in order to differentiate between Booleans and other instance requirements


class IntRequirement(interfaces.configuration.SimpleTypeRequirement):
    """A requirement type that contains a single integer."""

    instance_type: ClassVar[Type] = int


class StringRequirement(interfaces.configuration.SimpleTypeRequirement):
    """A requirement type that contains a single unicode string."""

    # TODO: Maybe add string length limits?
    instance_type: ClassVar[Type] = str


class URIRequirement(StringRequirement):
    """A requirement type that contains a single unicode string that is a valid
    URI."""

    # TODO: Maybe a a check that to unsatisfied that the path really is a URL?

    @classmethod
    def location_from_file(cls, filename: str) -> str:
        """Returns the URL location from a file parameter (which may be a URL)

        Args:
            filename: The path to the file (either an absolute, relative, or URL path)

        Returns:
            The URL for the location of the file
        """
        # We want to work in URLs, but we need to accept absolute and relative files (including on windows)
        single_location = parse.urlparse(filename, "")
        if single_location.scheme == "" or len(single_location.scheme) == 1:
            single_location = parse.urlparse(
                parse.urljoin("file:", request.pathname2url(os.path.abspath(filename)))
            )
        if single_location.scheme == "file":
            if not os.path.exists(request.url2pathname(single_location.path)):
                filename = request.url2pathname(single_location.path)
                if not filename:
                    raise ValueError("File URL looks incorrect (potentially missing /)")
                raise ValueError(f"File does not exist: {filename}")
        return parse.urlunparse(single_location)


class BytesRequirement(interfaces.configuration.SimpleTypeRequirement):
    """A requirement type that contains a byte string."""

    instance_type: ClassVar[Type] = bytes


class ListRequirement(interfaces.configuration.RequirementInterface):
    """Allows for a list of a specific type of requirement (all of which must
    be met for this requirement to be met) to be specified.

    This roughly correlates to allowing a number of arguments to follow a command line parameter,
    such as a list of integers or a list of strings.

    It is distinct from a multi-requirement which stores the subrequirements in a dictionary, not a list,
    and does not allow for a dynamic number of values.
    """

    def __init__(
        self,
        element_type: Type[interfaces.configuration.SimpleTypes] = str,
        max_elements: Optional[int] = 0,
        min_elements: Optional[int] = None,
        *args,
        **kwargs,
    ) -> None:
        """Constructs the object.

        Args:
            element_type: The (requirement) type of each element within the list
            max_elements; The maximum number of acceptable elements this list can contain
            min_elements: The minimum number of acceptable elements this list can contain
        """
        super().__init__(*args, **kwargs)
        if not issubclass(element_type, interfaces.configuration.BasicTypes):
            raise TypeError(
                "ListRequirements can only be populated with simple InstanceRequirements"
            )
        self.element_type: Type = element_type
        self.min_elements: int = min_elements or 0
        self.max_elements: Optional[int] = max_elements

    def unsatisfied(
        self, context: interfaces.context.ContextInterface, config_path: str
    ) -> Dict[str, interfaces.configuration.RequirementInterface]:
        """Check the types on each of the returned values and their number and
        then call the element type's check for each one."""
        config_path = interfaces.configuration.path_join(config_path, self.name)
        default = None
        value = self.config_value(context, config_path, default)
        if not value and self.min_elements > 0:
            vollog.log(
                constants.LOGLEVEL_V,
                "ListRequirement Unsatisfied - ListRequirement has non-zero min_elements",
            )
            return {config_path: self}
        if value is None and not self.optional:
            # We need to differentiate between no value and an empty list
            vollog.log(
                constants.LOGLEVEL_V,
                "ListRequirement Unsatisfied - Value was not specified",
            )
            return {config_path: self}
        elif value is None:
            context.config[config_path] = []
        if not isinstance(value, list):
            # TODO: Check this is the correct response for an error
            raise TypeError(f"Unexpected config value found: {repr(value)}")
        if not (self.min_elements <= len(value)):
            vollog.log(
                constants.LOGLEVEL_V,
                "TypeError - Too few values provided to list option.",
            )
            return {config_path: self}
        if self.max_elements and not (len(value) < self.max_elements):
            vollog.log(
                constants.LOGLEVEL_V,
                "TypeError - Too many values provided to list option.",
            )
            return {config_path: self}
        if not all([isinstance(element, self.element_type) for element in value]):
            vollog.log(
                constants.LOGLEVEL_V,
                "TypeError - At least one element in the list is not of the correct type.",
            )
            return {config_path: self}
        return {}


class ChoiceRequirement(interfaces.configuration.RequirementInterface):
    """Allows one from a choice of strings."""

    def __init__(self, choices: List[str], *args, **kwargs) -> None:
        """Constructs the object.

        Args:
            choices: A list of possible string options that can be chosen from
        """
        super().__init__(*args, **kwargs)
        if not isinstance(choices, list) or any(
            [not isinstance(choice, str) for choice in choices]
        ):
            raise TypeError("ChoiceRequirement takes a list of strings as choices")
        self.choices = choices

    def unsatisfied(
        self, context: interfaces.context.ContextInterface, config_path: str
    ) -> Dict[str, interfaces.configuration.RequirementInterface]:
        """Validates the provided value to ensure it is one of the available
        choices."""
        config_path = interfaces.configuration.path_join(config_path, self.name)
        value = self.config_value(context, config_path)
        if value not in self.choices:
            vollog.log(
                constants.LOGLEVEL_V,
                "ValueError - Value is not within the set of available choices",
            )
            return {config_path: self}
        return {}


class ComplexListRequirement(
    MultiRequirement,
    interfaces.configuration.ConfigurableRequirementInterface,
    metaclass=abc.ABCMeta,
):
    """Allows a variable length list of requirements."""

    def unsatisfied(
        self, context: interfaces.context.ContextInterface, config_path: str
    ) -> Dict[str, interfaces.configuration.RequirementInterface]:
        """Validates the provided value to ensure it is one of the available
        choices."""
        config_path = interfaces.configuration.path_join(config_path, self.name)
        ret_list = super().unsatisfied(context, config_path)
        if ret_list:
            return ret_list
        if self.config_value(context, config_path, None) is None or self.config_value(
            context,
            interfaces.configuration.path_join(config_path, "number_of_elements"),
        ):
            return {config_path: self}
        return {}

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        # This is not optional for the stacker to run, so optional must be marked as False
        return [
            IntRequirement(
                "number_of_elements",
                description="Determines how many layers are in this list",
                optional=False,
            )
        ]

    @abc.abstractmethod
    def construct(
        self, context: interfaces.context.ContextInterface, config_path: str
    ) -> None:
        """Method for constructing within the context any required elements
        from subrequirements."""

    @abc.abstractmethod
    def new_requirement(self, index) -> interfaces.configuration.RequirementInterface:
        """Builds a new requirement based on the specified index."""

    def build_configuration(
        self, context: interfaces.context.ContextInterface, config_path: str, _: Any
    ) -> interfaces.configuration.HierarchicalDict:
        result = interfaces.configuration.HierarchicalDict()
        num_elem_config_path = interfaces.configuration.path_join(
            config_path, self.name, "number_of_elements"
        )
        num_elements = context.config.get(num_elem_config_path, None)
        if num_elements is not None:
            result["number_of_elements"] = num_elements
            for i in range(num_elements):
                req = self.new_requirement(i)
                self.add_requirement(req)
                value_path = interfaces.configuration.path_join(
                    config_path, self.name, req.name
                )
                value = context.config.get(value_path, None)
                if value is not None:
                    result.splice(req.name, context.layers[value].build_configuration())
                    result[req.name] = value
        return result


class LayerListRequirement(ComplexListRequirement):
    """Allows a variable length list of layers that must exist."""

    def construct(
        self, context: interfaces.context.ContextInterface, config_path: str
    ) -> None:
        """Method for constructing within the context any required elements
        from subrequirements."""
        new_config_path = interfaces.configuration.path_join(config_path, self.name)
        num_layers_path = interfaces.configuration.path_join(
            new_config_path, "number_of_elements"
        )
        number_of_layers = context.config[num_layers_path]

        if not isinstance(number_of_layers, int):
            raise TypeError("Number of layers must be an integer")

        # Build all the layers that can be built
        for i in range(number_of_layers):
            layer_req = self.requirements.get(self.name + str(i), None)
            if layer_req is not None and isinstance(
                layer_req, TranslationLayerRequirement
            ):
                layer_req.construct(context, new_config_path)

    def new_requirement(self, index) -> interfaces.configuration.RequirementInterface:
        """Constructs a new requirement based on the specified index."""
        return TranslationLayerRequirement(
            name=self.name + str(index),
            description="Layer for swap space",
            optional=False,
        )


class TranslationLayerRequirement(
    interfaces.configuration.ConstructableRequirementInterface,
    interfaces.configuration.ConfigurableRequirementInterface,
):
    """Class maintaining the limitations on what sort of translation layers are
    acceptable."""

    def __init__(
        self,
        name: str,
        description: str = None,
        default: interfaces.configuration.ConfigSimpleType = None,
        optional: bool = False,
        oses: List = None,
        architectures: List = None,
    ) -> None:
        """Constructs a Translation Layer Requirement.

        The configuration option's value will be the name of the layer once it exists in the store

        Args:
            name: Name of the configuration requirement
            description: Description of the configuration requirement
            default: A default value (should not be used for TranslationLayers)
            optional: Whether the translation layer is required or not
            oses: A list of valid operating systems which can satisfy this requirement
            architectures: A list of valid architectures which can satisfy this requirement
        """
        if oses is None:
            oses = []
        if architectures is None:
            architectures = []
        self.oses = oses
        self.architectures = architectures
        super().__init__(name, description, default, optional)

    def unsatisfied(
        self, context: interfaces.context.ContextInterface, config_path: str
    ) -> Dict[str, interfaces.configuration.RequirementInterface]:
        """Validate that the value is a valid layer name and that the layer
        adheres to the requirements."""
        config_path = interfaces.configuration.path_join(config_path, self.name)
        value = self.config_value(context, config_path, None)
        if isinstance(value, str):
            if value not in context.layers:
                vollog.log(
                    constants.LOGLEVEL_V,
                    f"IndexError - Layer not found in memory space: {value}",
                )
                return {config_path: self}
            if (
                self.oses
                and context.layers[value].metadata.get("os", None) not in self.oses
            ):
                vollog.log(
                    constants.LOGLEVEL_V,
                    f"TypeError - Layer is not the required OS: {value}",
                )
                return {config_path: self}
            if (
                self.architectures
                and context.layers[value].metadata.get("architecture", None)
                not in self.architectures
            ):
                vollog.log(
                    constants.LOGLEVEL_V,
                    f"TypeError - Layer is not the required Architecture: {value}",
                )
                return {config_path: self}
            return {}

        if value is not None:
            vollog.log(
                constants.LOGLEVEL_V,
                f"TypeError - Translation Layer Requirement only accepts string labels: {repr(value)}",
            )
            return {config_path: self}

        # TODO: check that the space in the context lives up to the requirements for arch/os etc

        ### NOTE: This validate method has side effects (the dependencies can change)!!!

        self._validate_class(context, interfaces.configuration.parent_path(config_path))
        vollog.log(
            constants.LOGLEVEL_V,
            f"IndexError - No configuration provided: {config_path}",
        )
        return {config_path: self}

    def construct(
        self, context: interfaces.context.ContextInterface, config_path: str
    ) -> None:
        """Constructs the appropriate layer and adds it based on the class
        parameter."""
        config_path = interfaces.configuration.path_join(config_path, self.name)

        # Determine the layer name
        name = self.name
        counter = 2
        while name in context.layers:
            name = self.name + str(counter)
            counter += 1

        args = {"context": context, "config_path": config_path, "name": name}

        if any(
            [
                subreq.unsatisfied(context, config_path)
                for subreq in self.requirements.values()
                if not subreq.optional
            ]
        ):
            return None

        obj = self._construct_class(context, config_path, args)
        if obj is not None and isinstance(obj, interfaces.layers.DataLayerInterface):
            context.add_layer(obj)
            # This should already be done by the _construct_class method
            # context.config[config_path] = obj.name
        return None

    def build_configuration(
        self, context: interfaces.context.ContextInterface, _: str, value: Any
    ) -> interfaces.configuration.HierarchicalDict:
        """Builds the appropriate configuration for the specified
        requirement."""
        return context.layers[value].build_configuration()


class SymbolTableRequirement(
    interfaces.configuration.ConstructableRequirementInterface,
    interfaces.configuration.ConfigurableRequirementInterface,
):
    """Class maintaining the limitations on what sort of symbol spaces are
    acceptable."""

    def unsatisfied(
        self, context: interfaces.context.ContextInterface, config_path: str
    ) -> Dict[str, interfaces.configuration.RequirementInterface]:
        """Validate that the value is a valid within the symbol space of the
        provided context."""
        config_path = interfaces.configuration.path_join(config_path, self.name)
        value = self.config_value(context, config_path, None)
        if not isinstance(value, str) and value is not None:
            vollog.log(
                constants.LOGLEVEL_V,
                f"TypeError - SymbolTableRequirement only accepts string labels: {repr(value)}",
            )
            return {config_path: self}
        if value and value in context.symbol_space:
            # This is an expected situation, so return rather than raise
            return {}
        elif value:
            vollog.log(
                constants.LOGLEVEL_V,
                "IndexError - Value not present in the symbol space: {}".format(
                    value or ""
                ),
            )

        ### NOTE: This validate method has side effects (the dependencies can change)!!!

        self._validate_class(context, interfaces.configuration.parent_path(config_path))
        vollog.log(
            constants.LOGLEVEL_V,
            f"Symbol table requirement not yet fulfilled: {config_path}",
        )
        return {config_path: self}

    def construct(
        self, context: interfaces.context.ContextInterface, config_path: str
    ) -> None:
        """Constructs the symbol space within the context based on the
        subrequirements."""
        config_path = interfaces.configuration.path_join(config_path, self.name)
        # Determine the space name
        name = context.symbol_space.free_table_name(self.name)

        args = {"context": context, "config_path": config_path, "name": name}

        if any(
            [
                subreq.unsatisfied(context, config_path)
                for subreq in self.requirements.values()
                if not subreq.optional
            ]
        ):
            return None

        # Fill out the parameter for class creation
        if not isinstance(
            self.requirements["class"], interfaces.configuration.ClassRequirement
        ):
            raise TypeError(
                "Class requirement is not of type ClassRequirement: {}".format(
                    repr(self.requirements["class"])
                )
            )
        cls = self.requirements["class"].cls
        if cls is None:
            return None
        node_config = context.config.branch(config_path)
        for req in cls.get_requirements():
            if req.name in node_config.data and req.name != "class":
                args[req.name] = node_config.data[req.name]

        obj = self._construct_class(context, config_path, args)
        if obj is not None and isinstance(obj, interfaces.symbols.SymbolTableInterface):
            context.symbol_space.append(obj)
        return None

    def build_configuration(
        self, context: interfaces.context.ContextInterface, _: str, value: Any
    ) -> interfaces.configuration.HierarchicalDict:
        """Builds the appropriate configuration for the specified
        requirement."""
        return context.symbol_space[value].build_configuration()


class VersionRequirement(interfaces.configuration.RequirementInterface):
    def __init__(
        self,
        name: str,
        description: str = None,
        default: bool = False,
        optional: bool = False,
        component: Type[interfaces.configuration.VersionableInterface] = None,
        version: Optional[Tuple[int, ...]] = None,
    ) -> None:
        super().__init__(
            name=name, description=description, default=default, optional=optional
        )
        if component is None:
            raise TypeError("Component cannot be None")
        self._component: Type[interfaces.configuration.VersionableInterface] = component
        if version is None:
            raise TypeError("Version cannot be None")
        self._version = version

    def unsatisfied(
        self, context: interfaces.context.ContextInterface, config_path: str
    ) -> Dict[str, interfaces.configuration.RequirementInterface]:
        # Mypy doesn't appreciate our classproperty implementation, self._plugin.version has no type
        config_path = interfaces.configuration.path_join(config_path, self.name)
        if not self.matches_required(self._version, self._component.version):
            return {config_path: self}
        context.config[interfaces.configuration.path_join(config_path, self.name)] = (
            True
        )
        return {}

    @classmethod
    def matches_required(
        cls, required: Tuple[int, ...], version: Tuple[int, int, int]
    ) -> bool:
        if len(required) > 0 and version[0] != required[0]:
            return False
        if len(required) > 1 and version[1] < required[1]:
            return False
        return True


class PluginRequirement(VersionRequirement):
    def __init__(
        self,
        name: str,
        description: str = None,
        default: bool = False,
        optional: bool = False,
        plugin: Type[interfaces.plugins.PluginInterface] = None,
        version: Optional[Tuple[int, ...]] = None,
    ) -> None:
        super().__init__(
            name=name,
            description=description,
            default=default,
            optional=optional,
            component=plugin,
            version=version,
        )

    def unsatisfied(
        self, context: interfaces.context.ContextInterface, config_path: str
    ) -> Dict[str, interfaces.configuration.RequirementInterface]:
        result = super().unsatisfied(context, config_path)
        if not result:
            component: Type[interfaces.plugins.PluginInterface] = self._component
            for requirement in component.get_requirements():
                if isinstance(requirement, PluginRequirement):
                    result.update(
                        requirement.unsatisfied(
                            context,
                            interfaces.configuration.path_join(config_path, self.name),
                        )
                    )
        if result:
            result[config_path] = self
        return result


class ModuleRequirement(
    interfaces.configuration.ConstructableRequirementInterface,
    interfaces.configuration.ConfigurableRequirementInterface,
):
    def __init__(
        self,
        name: str,
        description: str = None,
        default: bool = False,
        architectures: Optional[List[str]] = None,
        optional: bool = False,
    ):
        super().__init__(
            name=name, description=description, default=default, optional=optional
        )
        self.add_requirement(
            TranslationLayerRequirement(name="layer_name", architectures=architectures)
        )
        self.add_requirement(SymbolTableRequirement(name="symbol_table_name"))

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            IntRequirement(name="offset"),
        ]

    def unsatisfied(
        self, context: "interfaces.context.ContextInterface", config_path: str
    ) -> Dict[str, interfaces.configuration.RequirementInterface]:
        """Validate that the value is a valid module"""
        config_path = interfaces.configuration.path_join(config_path, self.name)
        value = self.config_value(context, config_path, None)
        if isinstance(value, str):
            if value not in context.modules:
                vollog.log(
                    constants.LOGLEVEL_V,
                    f"IndexError - Module not found in context: {value}",
                )
                return {config_path: self}
            return {}

        if value is not None:
            vollog.log(
                constants.LOGLEVEL_V,
                "TypeError - Module Requirement only accepts string labels: {}".format(
                    repr(value)
                ),
            )
            return {config_path: self}

        result = {}
        for subreq in self._requirements:
            req_unsatisfied = self._requirements[subreq].unsatisfied(
                context, config_path
            )
            if req_unsatisfied:
                result.update(req_unsatisfied)
        if not result:
            vollog.log(
                constants.LOGLEVEL_V,
                f"IndexError - No configuration provided: {config_path}",
            )
            result = {config_path: self}

        ### NOTE: This validate method has side effects (the dependencies can change)!!!

        self._validate_class(context, interfaces.configuration.parent_path(config_path))

        return result

    def construct(
        self, context: interfaces.context.ContextInterface, config_path: str
    ) -> None:
        """Constructs the appropriate layer and adds it based on the class parameter."""
        config_path = interfaces.configuration.path_join(config_path, self.name)

        # Determine the layer name
        name = self.name
        counter = 2
        while name in context.modules:
            name = self.name + str(counter)
            counter += 1

        args = {"context": context, "config_path": config_path, "name": name}

        if any(
            [
                subreq.unsatisfied(context, config_path)
                for subreq in self.requirements.values()
                if not subreq.optional
            ]
        ):
            return None

        obj = self._construct_class(context, config_path, args)
        if obj is not None and isinstance(obj, interfaces.context.ModuleInterface):
            context.add_module(obj)
            # This should already be done by the _construct_class method
            # context.config[config_path] = obj.name
        return None

    def build_configuration(
        self, context: "interfaces.context.ContextInterface", _: str, value: Any
    ) -> interfaces.configuration.HierarchicalDict:
        """Builds the appropriate configuration for the specified
        requirement."""
        return context.modules[value].build_configuration()
