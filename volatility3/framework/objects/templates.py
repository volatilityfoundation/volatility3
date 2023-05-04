# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
import functools
import logging
from typing import Any, ClassVar, Dict, List, Type

from volatility3.framework import interfaces, exceptions, constants

vollog = logging.getLogger(__name__)


class ObjectTemplate(interfaces.objects.Template):
    """Factory class that produces objects that adhere to the Object interface
    on demand.

    This is effectively a method of currying, but adds more structure to avoid abuse.
    It also allows inspection of information that should already be known:

      * Type size
      * Members
      * etc
    """

    def __init__(
        self,
        object_class: Type[interfaces.objects.ObjectInterface],
        type_name: str,
        **arguments,
    ) -> None:
        arguments["object_class"] = object_class
        super().__init__(type_name=type_name, **arguments)

        proxy_cls = self.vol.object_class.VolTemplateProxy
        for method_name in proxy_cls._methods:
            setattr(
                self,
                method_name,
                functools.partial(getattr(proxy_cls, method_name), self),
            )

    @property
    def size(self) -> int:
        """Returns the children of the templated object (see :class:`~volatilit
        y.framework.interfaces.objects.ObjectInterface.VolTemplateProxy`)"""
        return self.vol.object_class.VolTemplateProxy.size(self)

    @property
    def children(self) -> List[interfaces.objects.Template]:
        """Returns the children of the templated object (see :class:`~volatilit
        y.framework.interfaces.objects.ObjectInterface.VolTemplateProxy`)"""
        return self.vol.object_class.VolTemplateProxy.children(self)

    def relative_child_offset(self, child: str) -> int:
        """Returns the relative offset of a child of the templated object (see
        :class:`~volatility3.framework.interfaces.objects.ObjectInterface.VolTem
        plateProxy`)"""
        return self.vol.object_class.VolTemplateProxy.relative_child_offset(self, child)

    def child_template(self, child: str) -> interfaces.objects.Template:
        """Returns the template of a child of the templated object (see
        :class:`~volatility3.framework.interfaces.objects.ObjectInterface.VolTem
        plateProxy`)"""
        return self.vol.object_class.VolTemplateProxy.child_template(self, child)

    def replace_child(
        self,
        old_child: interfaces.objects.Template,
        new_child: interfaces.objects.Template,
    ) -> None:
        """Replaces `old_child` for `new_child` in the templated object's child
        list (see :class:`~volatility3.framework.interfaces.objects.ObjectInterf
        ace.VolTemplateProxy`)"""
        return self.vol.object_class.VolTemplateProxy.replace_child(
            self, old_child, new_child
        )

    def has_member(self, member_name: str) -> bool:
        """Returns whether the object would contain a member called
        member_name."""
        return self.vol.object_class.VolTemplateProxy.has_member(self, member_name)

    def __call__(
        self,
        context: interfaces.context.ContextInterface,
        object_info: interfaces.objects.ObjectInformation,
    ) -> interfaces.objects.ObjectInterface:
        """Constructs the object.

        Returns: an object adhering to the :class:`~volatility3.framework.interfaces.objects.ObjectInterface`
        """
        arguments: Dict[str, Any] = {}
        for arg in self.vol:
            if arg != "object_class":
                arguments[arg] = self.vol[arg]
        return self.vol.object_class(
            context=context, object_info=object_info, **arguments
        )


class ReferenceTemplate(interfaces.objects.Template):
    """Factory class that produces objects based on a delayed reference type.

    Attempts to access any standard attributes of a resolved template will result in a
    :class:`~volatility3.framework.exceptions.SymbolError`.
    """

    @property
    def children(self) -> List[interfaces.objects.Template]:
        return []

    def _unresolved(self, *args, **kwargs) -> Any:
        """Referenced symbols must be appropriately resolved before they can
        provide information such as size This is because the size request has
        no context within which to determine the actual symbol structure."""
        type_name = self.vol.type_name.split(constants.BANG)
        table_name = None
        if len(type_name) == 2:
            table_name = type_name[0]
        symbol_name = type_name[-1]
        raise exceptions.SymbolError(
            symbol_name,
            table_name,
            f"Template contains no information about its structure: {self.vol.type_name}",
        )

    size: ClassVar[Any] = property(_unresolved)
    replace_child: ClassVar[Any] = _unresolved
    relative_child_offset: ClassVar[Any] = _unresolved
    child_template: ClassVar[Any] = _unresolved
    has_member: ClassVar[Any] = _unresolved

    def __call__(
        self,
        context: interfaces.context.ContextInterface,
        object_info: interfaces.objects.ObjectInformation,
    ):
        template = context.symbol_space.get_type(self.vol.type_name)
        return template(context=context, object_info=object_info)
