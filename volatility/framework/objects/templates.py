import logging
import typing

from volatility.framework import interfaces, validity, exceptions

vollog = logging.getLogger(__name__)


class ObjectTemplate(interfaces.objects.Template, validity.ValidityRoutines):
    """Factory class that produces objects that adhere to the Object interface on demand

       This is effectively a method of currying, but adds more structure to avoid abuse.
       It also allows inspection of information that should already be known:

         * Type size
         * Members
         * etc
    """

    def __init__(self,
                 object_class: typing.Type[interfaces.objects.ObjectInterface],
                 type_name: str,
                 **arguments) -> None:
        super().__init__(type_name = type_name, **arguments)
        self._check_class(object_class, interfaces.objects.ObjectInterface)
        self._arguments['object_class'] = object_class

    @property
    def size(self) -> int:
        """Returns the children of the templated object (see :class:`~volatility.framework.interfaces.objects.ObjectInterface.VolTemplateProxy`)"""
        return self.vol.object_class.VolTemplateProxy.size(self)

    @property
    def children(self) -> typing.List[interfaces.objects.Template]:
        """Returns the children of the templated object (see :class:`~volatility.framework.interfaces.objects.ObjectInterface.VolTemplateProxy`)
        """
        return self.vol.object_class.VolTemplateProxy.children(self)

    def relative_child_offset(self, child: str) -> int:
        """Returns the relative offset of a child of the templated object (see :class:`~volatility.framework.interfaces.objects.ObjectInterface.VolTemplateProxy`)
        """
        return self.vol.object_class.VolTemplateProxy.relative_child_offset(self, child)

    def replace_child(self,
                      old_child: interfaces.objects.Template,
                      new_child: interfaces.objects.Template) -> None:
        """Replaces `old_child` for `new_child` in the templated object's child list (see :class:`~volatility.framework.interfaces.objects.ObjectInterface.VolTemplateProxy`)
        """
        return self.vol.object_class.VolTemplateProxy.replace_child(self, old_child, new_child)

    def __call__(self,
                 context: interfaces.context.ContextInterface,
                 object_info: interfaces.objects.ObjectInformation) -> interfaces.objects.ObjectInterface:
        """Constructs the object

           Returns: an object adhereing to the :class:`~volatility.framework.interfaces.objects.ObjectInterface`
        """
        arguments = {}  # type: typing.Dict[str, typing.Any]
        arguments.update(self.vol)
        del arguments['object_class']
        return self.vol.object_class(context = context,
                                     object_info = object_info,
                                     **arguments)


class ReferenceTemplate(interfaces.objects.Template):
    """Factory class that produces objects based on a delayed reference type

    Attempts to access any standard attributes of a resolved template will result in a
    :class:`~volatility.framework.exceptions.SymbolError`.
    """

    @property
    def children(self) -> typing.List[interfaces.objects.Template]:
        return []

    def _unresolved(self, *args, **kwargs) -> typing.Any:
        """Referenced symbols must be appropriately resolved before they can provide information such as size
           This is because the size request has no context within which to determine the actual symbol structure.
        """
        raise exceptions.SymbolError(
            "Template contains no information about its structure: {}".format(self.vol.type_name))

    size = property(_unresolved)  # type: typing.ClassVar[typing.Any]
    replace_child = _unresolved  # type: typing.ClassVar[typing.Any]
    relative_child_offset = _unresolved  # type: typing.ClassVar[typing.Any]

    def __call__(self,
                 context: interfaces.context.ContextInterface,
                 object_info: interfaces.objects.ObjectInformation):
        template = context.symbol_space.get_type(self.vol.type_name)
        return template(context = context, object_info = object_info)
