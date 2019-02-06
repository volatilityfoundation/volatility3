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
"""In-memory artifacts from OSX systems"""
from typing import Iterator, Tuple, Any, Generator, List

from volatility.framework import exceptions, renderers, interfaces
from volatility.framework.configuration import requirements
from volatility.framework.interfaces import plugins
from volatility.framework.objects import utility
from volatility.plugins.mac import pslist


class Psaux(plugins.PluginInterface):
    """Recovers program command line arguments"""

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.TranslationLayerRequirement(
                name = 'primary', description = 'Memory layer for the kernel', architectures = ["Intel32", "Intel64"]),
            requirements.SymbolTableRequirement(name = "darwin", description = "Mac kernel symbols")
        ]

    def _generator(self, tasks: Iterator[Any]) -> Generator[Tuple[int, Tuple[int, str, int, str]], None, None]:
        for task in tasks:
            proc_layer_name = task.add_process_layer()
            if proc_layer_name is None:
                continue

            proc_layer = self.context.memory[proc_layer_name]

            argsstart = task.user_stack - task.p_argslen

            if not proc_layer.is_valid(argsstart) or task.p_argslen == 0 or task.p_argc == 0:
                continue

            # Add one because the first two are usually duplicates
            argc = task.p_argc + 1

            # smear protection
            if argc > 1024:
                continue

            task_name = utility.array_to_string(task.p_comm)

            args = []

            while argc > 0:
                try:
                    arg = proc_layer.read(argsstart, 256)
                except exceptions.PagedInvalidAddressException:
                    break

                idx = arg.find(b'\x00')
                if idx != -1:
                    arg = arg[:idx]

                argsstart += len(str(arg)) + 1

                # deal with the stupid alignment (leading nulls) and arg duplication
                if len(args) == 0:
                    while argsstart < task.user_stack:
                        try:
                            check = proc_layer.read(argsstart, 1)
                        except exceptions.PagedInvalidAddressException:
                            break

                        if check != b"\x00":
                            break

                        argsstart = argsstart + 1

                    args.append(arg)

                # also check for initial duplicates since OS X is painful
                elif arg != args[0]:
                    args.append(arg)

                argc = argc - 1

            args_str = " ".join([s.decode("utf-8") for s in args])

            yield (0, (task.p_pid, task_name, task.p_argc, args_str))

    def run(self) -> renderers.TreeGrid:
        filter_func = pslist.PsList.create_filter([self.config.get('pid', None)])

        plugin = pslist.PsList.list_tasks

        return renderers.TreeGrid(
            [("PID", int), ("Process", str), ("Argc", int), ("Arguments", str)],
            self._generator(plugin(self.context, self.config['primary'], self.config['darwin'], filter = filter_func)))
