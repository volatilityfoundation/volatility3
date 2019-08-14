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

import inspect
from typing import Callable, Dict

from volatility.cli.volshell import shellplugin
from volatility.framework.configuration import requirements


class Volshell(shellplugin.Volshell):
    """Shell environment to directly interact with a windows memory image"""

    @classmethod
    def get_requirements(cls):
        return (super().get_requirements() + [
            requirements.SymbolTableRequirement(name = "nt_symbols", description = "Windows kernel symbols"),
            requirements.IntRequirement(name = 'pid', description = "Process ID", optional = True)
        ])

    def list_processes(self):
        """Lists all the processes in the primary layer"""

        # We only use the object factory to demonstrate how to use one
        layer_name = self.config['primary']
        kvo = self.context.layers[layer_name].config['kernel_virtual_offset']
        ntkrnlmp = self.context.module(self.config['nt_symbols'], layer_name = layer_name, offset = kvo)

        ps_aph_offset = ntkrnlmp.get_symbol("PsActiveProcessHead").address
        list_entry = ntkrnlmp.object(object_type = "_LIST_ENTRY", offset = ps_aph_offset)

        # This is example code to demonstrate how to use symbol_space directly, rather than through a module:
        #
        # ```
        # reloff = self.context.symbol_space.get_type(
        #          self.config['nt_symbols'] + constants.BANG + "_EPROCESS").relative_child_offset(
        #          "ActiveProcessLinks")
        # ```
        #
        # Note: "nt!_EPROCESS" could have been used, but would rely on the "nt" symbol table not already
        # having been present.  Strictly, the value of the requirement should be joined with the BANG character
        # defined in the constants file
        reloff = ntkrnlmp.get_type("_EPROCESS").relative_child_offset("ActiveProcessLinks")
        eproc = ntkrnlmp.object(object_type = "_EPROCESS", offset = list_entry.vol.offset - reloff, absolute = True)

        for proc in eproc.ActiveProcessLinks:
            yield proc

    def load_functions(self) -> Dict[str, Callable]:
        result = super().load_functions()
        result.update({'ps': lambda: list(self.list_processes())})
        return result

    def run(self, additional_locals = None):
        # Determine locals
        curframe = inspect.currentframe()

        # Provide some OS-agnostic convenience elements for ease
        layer_name = self.config['primary']
        kvo = self.context.layers[layer_name].config['kernel_virtual_offset']
        nt = self.context.module(self.config['nt_symbols'], layer_name = layer_name, offset = kvo)
        ps = lambda: list(self.list_processes())

        pid = self.config.get('pid', None)
        eproc = None
        if pid:
            for _x in ps():
                if _x.UniqueProcessId == pid:
                    eproc = _x
                    break

        return super().run(curframe.f_locals)
