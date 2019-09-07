# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl_v1.0
#

import code
import inspect
from typing import Any, Callable, Dict, List

from volatility.framework import renderers, interfaces
from volatility.framework.configuration import requirements


class Volshell(interfaces.plugins.PluginInterface):
    """Shell environment to directly interact with a memory image."""

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.TranslationLayerRequirement(
                name = 'primary', description = 'Memory layer for the kernel', architectures = ["Intel32", "Intel64"])
        ]

    def run(self, additional_locals: Dict[str, Any] = None) -> interfaces.renderers.TreeGrid:
        """Runs the interactive volshell plugin.

        Returns:
            Return a TreeGrid but this is always empty since the point of this plugin is to run interactively
        """

        # Provide some OS-agnostic convenience elements for ease
        context = self.context
        config = self.config
        layer_name = self.config['primary']
        kvo = context.layers[layer_name].config.get('kernel_virtual_offset')
        members = lambda x: list(sorted(x.vol.members))

        # Determine locals
        curframe = inspect.currentframe()
        vars = {}  # type: Dict[str, Any]
        if curframe:
            vars = curframe.f_globals.copy()
            vars.update(curframe.f_locals)
        if additional_locals is not None:
            vars.update(additional_locals)

        vars.update(self.load_functions())

        # Try to enable tab completion
        try:
            import readline
        except ImportError:
            pass
        else:
            import rlcompleter
            completer = rlcompleter.Completer(namespace = vars)
            readline.set_completer(completer.complete)
            readline.parse_and_bind("tab: complete")
            print("Readline imported successfully")

        # TODO: provide help, consider generic functions (pslist?) and/or providing windows/linux functions

        code.interact(local = vars)

        return renderers.TreeGrid([], None)

    def load_functions(self) -> Dict[str, Callable]:
        """Returns a dictionary listing the functions to be added to the
        environment."""
        return {"dt": self.display_type}

    @staticmethod
    def display_type(object: interfaces.objects.ObjectInterface):
        """Display Type."""
        longest_member = longest_offset = 0
        for member in object.vol.members:
            relative_offset, member_type = object.vol.members[member]
            longest_member = max(len(member), longest_member)
            longest_offset = max(len(hex(relative_offset)), longest_offset)

        for member in object.vol.members:
            relative_offset, member_type = object.vol.members[member]
            len_offset = len(hex(relative_offset))
            len_member = len(member)
            print(" " * (longest_offset - len_offset), hex(relative_offset), "\t\t", member,
                  " " * (longest_member - len_member), "\t\t", member_type.vol.type_name)
