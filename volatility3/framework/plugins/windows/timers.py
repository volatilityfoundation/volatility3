# This file is Copyright 2022 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

import logging

from typing import Iterator, List, Tuple

from volatility3.framework import renderers, interfaces
from volatility3.framework.configuration import requirements
from volatility3.framework.renderers import format_hints

vollog = logging.getLogger(__name__)

class Timers(interfaces.plugins.PluginInterface):
    """Print kernel timers and associated module DPCs"""

    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 0)

    @classmethod
    def get_requirements(cls)-> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(name = 'kernel', description = 'Windows kernel',
                                           architectures = ["Intel32", "Intel64"])         
        ]
    
    def _generator(self) -> Iterator[Tuple]:
        yield(0, [])
    
    def run(self)-> renderers.TreeGrid:
        return renderers.TreeGrid([
            ("Offset", format_hints.Hex),
            ("DueTime", str),
            ("Period(ms)", str),
            ("Signaled", str),
            ("Routine", int),
            ("Module", format_hints.Hex)
        ], self._generator())
