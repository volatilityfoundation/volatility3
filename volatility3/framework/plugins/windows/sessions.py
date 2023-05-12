# This file is Copyright 2022 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

import datetime
import logging

from volatility3.framework import renderers, interfaces
from volatility3.framework.configuration import requirements
from volatility3.framework.objects import utility
from volatility3.plugins.windows import pslist
from volatility3.plugins import timeliner

vollog = logging.getLogger(__name__)


class Sessions(interfaces.plugins.PluginInterface, timeliner.TimeLinerInterface):
    """lists Processes with Session information extracted from Environmental Variables"""

    _required_framework_version = (2, 0, 0)

    @classmethod
    def get_requirements(cls):
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Windows kernel",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.PluginRequirement(
                name="pslist", plugin=pslist.PsList, version=(2, 0, 0)
            ),
            requirements.ListRequirement(
                name="pid",
                element_type=int,
                description="Process IDs to include (all other processes are excluded)",
                optional=True,
            ),
        ]

    def _generator(self):
        kernel = self.context.modules[self.config["kernel"]]
        filter_func = pslist.PsList.create_pid_filter(self.config.get("pid", None))

        # Collect all the values as we will want to group them later
        sessions = {}

        for proc in pslist.PsList.list_processes(
            self.context,
            kernel.layer_name,
            kernel.symbol_table_name,
            filter_func=filter_func,
        ):
            session_id = proc.get_session_id()

            # Detect RDP, Console or set default value
            session_type = renderers.NotAvailableValue()

            # Construct Username from Process Env
            user_domain = ""
            user_name = ""

            for var, val in proc.environment_variables():
                if var.lower() == "username":
                    user_name = val
                elif var.lower() == "userdomain":
                    user_domain = val
                if var.lower() == "sessionname":
                    session_type = val

            # Concat Domain and User
            full_user = f"{user_domain}/{user_name}"
            if full_user == "/":
                full_user = renderers.NotAvailableValue()

            # Collect all the values in to a row we can yield after sorting.
            row = {
                "session_id": session_id,
                "process_id": proc.UniqueProcessId,
                "process_name": utility.array_to_string(proc.ImageFileName),
                "user_name": full_user,
                "process_start": proc.get_create_time(),
                "session_type": session_type,
            }

            # Add row to correct session so we can sort it later
            if session_id in sessions:
                sessions[session_id].append(row)
            else:
                sessions[session_id] = [row]

        # Group and yield each row
        for rows in sessions.values():
            for row in rows:
                yield 0, (
                    row.get("session_id"),
                    row.get("session_type"),
                    row.get("process_id"),
                    row.get("process_name"),
                    row.get("user_name"),
                    row.get("process_start"),
                )

    def generate_timeline(self):
        for row in self._generator():
            _depth, row_data = row
            # Only add to timeline if we have the username
            # Without the user context PSList output is identical
            if isinstance(row_data[4], str):
                description = f"Process: {row_data[2]} {row_data[3]} started by user {row_data[4]}"
                yield (description, timeliner.TimeLinerType.CREATED, row_data[5])

    def run(self):
        return renderers.TreeGrid(
            [
                ("Session ID", int),
                ("Session Type", str),
                ("Process ID", int),
                ("Process", str),
                ("User Name", str),
                ("Create Time", datetime.datetime),
            ],
            self._generator(),
        )
