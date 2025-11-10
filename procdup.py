import logging
from typing import List
from volatility3.framework import interfaces, renderers
from volatility3.framework.configuration import requirements

vollog = logging.getLogger(__name__)

class Test(interfaces.plugins.PluginInterface):
    """Test plugin to verify plugin loading."""
    
    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 0)
    
    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Windows kernel module",
                architectures=["Intel32", "Intel64"],
            ),
        ]
    
    def _generator(self):
        yield (0, ("Test", "Success", "Plugin is working"))
    
    def run(self):
        return renderers.TreeGrid(
            [("Status", str), ("Message", str), ("Result", str)],
            self._generator()
        )