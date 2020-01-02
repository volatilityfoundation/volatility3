import logging
from typing import List

from volatility.framework import interfaces
from volatility.framework.configuration import requirements
from volatility.plugins.windows import pslist

from pypykatz.pypykatz import pypykatz as pparser

vollog = logging.getLogger(__name__)

class pypykatz(interfaces.plugins.PluginInterface):

	@classmethod
	def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
		return [
			requirements.TranslationLayerRequirement(name = 'primary',
													 description = 'Memory layer for the kernel',
													 architectures = ["Intel32", "Intel64"]),
			requirements.SymbolTableRequirement(name = "nt_symbols", description = "Windows kernel symbols"),
			requirements.PluginRequirement(name = 'pslist',
							   plugin = pslist.PsList,
							   version = (1, 0, 0)),
		]
	
	def run(self):
		return pparser.go_volatility3(self)