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

import json
import logging
from typing import List

from volatility.framework import renderers, interfaces
from volatility.framework.configuration import requirements
from volatility.framework.interfaces import plugins

vollog = logging.getLogger(__name__)


class ConfigWriter(plugins.PluginInterface):
    """Runs the automagics and both prints and outputs configuration in the output directory"""

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.TranslationLayerRequirement(
                name = 'primary', description = 'Memory layer for the kernel', architectures = ["Intel32", "Intel64"]),
            requirements.BooleanRequirement(
                name = 'extra', description = 'Outputs whole configuration tree', default = False, optional = True)
        ]

    def _generator(self):
        filename = "config.json"
        config = dict(self.build_configuration())
        if self.config.get('extra', False):
            vollog.debug("Outputting additional information, this will NOT work with the -c option")
            config = dict(self.context.config)
            filename = "config.extra"
        try:
            filedata = plugins.FileInterface(filename)
            filedata.data.write(bytes(json.dumps(config, sort_keys = True, indent = 2), 'latin-1'))
            self.produce_file(filedata)
        except Exception:
            vollog.warn("Unable to JSON encode configuration")

        for k, v in config.items():
            yield (0, (k, json.dumps(v)))

    def run(self):
        return renderers.TreeGrid([("Key", str), ("Value", str)], self._generator())
