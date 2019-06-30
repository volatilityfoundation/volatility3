# This file was contributed to the Volatility Framework Version 3.
# Copyright (C) 2018 Volatility Foundation.
#
# THE LICENSED WORK IS PROVIDED UNDER THE TERMS OF THE Volatility Contributors
# Public License V1.0("LICENSE") AS FIRST COMPLETED BY: Volatility Foundation,
# Inc. ANY USE, PUBLIC DISPLAY, PUBLIC PERFORMANCE, REPRODUCTION OR DISTRIBUTION
# OF, OR PREPARATION OF SUBSEQUENT WORKS, DERIVATIVE WORKS OR DERIVED WORKS BASED
# ON, THE LICENSED WORK CONSTITUTES RECIPIENT'S ACCEPTANCE OF THIS LICENSE AND ITS
# TERMS, WHETHER OR NOT SUCH RECIPIENT READS THE TERMS OF THE LICENSE. "LICENSED
# WORK,” “RECIPIENT" AND “DISTRIBUTOR" ARE DEFINED IN THE LICENSE. A COPY OF THE
# LICENSE IS LOCATED IN THE TEXT FILE ENTITLED "LICENSE.txt" ACCOMPANYING THE
# CONTENTS OF THIS FILE. IF A COPY OF THE LICENSE DOES NOT ACCOMPANY THIS FILE, A
# COPY OF THE LICENSE MAY ALSO BE OBTAINED AT THE FOLLOWING WEB SITE:
# https://www.volatilityfoundation.org/license/vcpl_v1.0
#
# Software distributed under the License is distributed on an "AS IS" basis,
# WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License for the
# specific language governing rights and limitations under the License.
#
import logging
from typing import Any, ClassVar, Dict, List, Type

from volatility.framework import interfaces, exceptions

vollog = logging.getLogger(__name__)


class ObjectTemplate(interfaces.objects.Template):
    """Factory class that produces objects that adhere to the Object interface on demand

       This is effectively a method of currying, but adds more structure to avoid abuse.
       It also allows inspection of information that should already be known:

         * Type size
         * Members
         * etc
    """

    def __init__(self, object_class: Type[interfaces.objects.ObjectInterface], type_name: str, **arguments) -> None:
        super().__init__(type_name = type_name, **arguments)
        self._arguments['object_class'] = object_class

        # proxy_cls = self.vol.object_class.VolTemplateProxy
        # for method_name in dir(proxy_cls):
        #     if (method_name not in dir(interfaces.objects.ObjectInterface.VolTemplateProxy)
        #             and callable(getattr(proxy_cls, method_name)) and not method_name.startswith('_')):
        #         setattr(self, method_name, functools.partial(getattr(proxy_cls, method_name), self))

    @property
    def size(self) -> int:
        """Returns the children of the templated object (see :class:`~volatility.framework.interfaces.objects.ObjectInterface.VolTemplateProxy`)"""
        return self.vol.object_class.VolTemplateProxy.size(self)

    @property
    def children(self) -> List[interfaces.objects.Template]:
        """Returns the children of the templated object (see :class:`~volatility.framework.interfaces.objects.ObjectInterface.VolTemplateProxy`)
        """
        return self.vol.object_class.VolTemplateProxy.children(self)

    def relative_child_offset(self, child: str) -> int:
        """Returns the relative offset of a child of the templated object (see :class:`~volatility.framework.interfaces.objects.ObjectInterface.VolTemplateProxy`)
        """
        return self.vol.object_class.VolTemplateProxy.relative_child_offset(self, child)

    def replace_child(self, old_child: interfaces.objects.Template, new_child: interfaces.objects.Template) -> None:
        """Replaces `old_child` for `new_child` in the templated object's child list (see :class:`~volatility.framework.interfaces.objects.ObjectInterface.VolTemplateProxy`)
        """
        return self.vol.object_class.VolTemplateProxy.replace_child(self, old_child, new_child)

    def has_member(self, member_name: str) -> bool:
        """Returns whether the object would contain a member called member_name
        """
        return self.vol.object_class.VolTemplateProxy.has_member(self, member_name)

    def __call__(self, context: interfaces.context.ContextInterface,
                 object_info: interfaces.objects.ObjectInformation) -> interfaces.objects.ObjectInterface:
        """Constructs the object

           Returns: an object adhereing to the :class:`~volatility.framework.interfaces.objects.ObjectInterface`
        """
        arguments = {}  # type: Dict[str, Any]
        for arg in self.vol:
            if arg != 'object_class':
                arguments[arg] = self.vol[arg]
        return self.vol.object_class(context = context, object_info = object_info, **arguments)


class ReferenceTemplate(interfaces.objects.Template):
    """Factory class that produces objects based on a delayed reference type

    Attempts to access any standard attributes of a resolved template will result in a
    :class:`~volatility.framework.exceptions.SymbolError`.
    """

    @property
    def children(self) -> List[interfaces.objects.Template]:
        return []

    def _unresolved(self, *args, **kwargs) -> Any:
        """Referenced symbols must be appropriately resolved before they can provide information such as size
           This is because the size request has no context within which to determine the actual symbol structure.
        """
        raise exceptions.SymbolError("Template contains no information about its structure: {}".format(
            self.vol.type_name))

    size = property(_unresolved)  # type: ClassVar[Any]
    replace_child = _unresolved  # type: ClassVar[Any]
    relative_child_offset = _unresolved  # type: ClassVar[Any]
    has_member = _unresolved  # type: ClassVar[Any]

    def __call__(self, context: interfaces.context.ContextInterface, object_info: interfaces.objects.ObjectInformation):
        template = context.symbol_space.get_type(self.vol.type_name)
        return template(context = context, object_info = object_info)
