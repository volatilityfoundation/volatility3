# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
# Creator: Aviel Zohar (memoryforensicsanalysis@gmail.com) # Fix vol2 plugin to vol3
import logging
from typing import Callable, List, Generator, Iterable

from volatility.framework import renderers, interfaces, objects
from volatility.framework.configuration import requirements
from volatility.framework.objects import utility
from volatility.framework.renderers import format_hints
from volatility.plugins.windows import pslist

vollog = logging.getLogger(__name__)

PRIVILEGE_INFO = {
    2: ('SeCreateTokenPrivilege', "Create a token object"),
    3: ('SeAssignPrimaryTokenPrivilege', "Replace a process-level token"),
    4: ('SeLockMemoryPrivilege', "Lock pages in memory"),
    5: ('SeIncreaseQuotaPrivilege', "Increase quotas"),
    6: ('SeMachineAccountPrivilege', "Add workstations to the domain"),
    7: ('SeTcbPrivilege', "Act as part of the operating system"),
    8: ('SeSecurityPrivilege', "Manage auditing and security log"),
    9: ('SeTakeOwnershipPrivilege', "Take ownership of files/objects"),
    10: ('SeLoadDriverPrivilege', "Load and unload device drivers"),
    11: ('SeSystemProfilePrivilege', "Profile system performance"),
    12: ('SeSystemtimePrivilege', "Change the system time"),
    13: ('SeProfileSingleProcessPrivilege', "Profile a single process"),
    14: ('SeIncreaseBasePriorityPrivilege', "Increase scheduling priority"),
    15: ('SeCreatePagefilePrivilege', "Create a pagefile"),
    16: ('SeCreatePermanentPrivilege', "Create permanent shared objects"),
    17: ('SeBackupPrivilege', "Backup files and directories"),
    18: ('SeRestorePrivilege', "Restore files and directories"),
    19: ('SeShutdownPrivilege', "Shut down the system"),
    20: ('SeDebugPrivilege', "Debug programs"),
    21: ('SeAuditPrivilege', "Generate security audits"),
    22: ('SeSystemEnvironmentPrivilege', "Edit firmware environment values"),
    23: ('SeChangeNotifyPrivilege', "Receive notifications of changes to files or directories"),
    24: ('SeRemoteShutdownPrivilege', "Force shutdown from a remote system"),
    25: ('SeUndockPrivilege', "Remove computer from docking station"),
    26: ('SeSyncAgentPrivilege', "Synch directory service data"),
    27: ('SeEnableDelegationPrivilege', "Enable user accounts to be trusted for delegation"),
    28: ('SeManageVolumePrivilege', "Manage the files on a volume"),
    29: ('SeImpersonatePrivilege', "Impersonate a client after authentication"),
    30: ('SeCreateGlobalPrivilege', "Create global objects"),
    31: ('SeTrustedCredManAccessPrivilege', "Access Credential Manager as a trusted caller"),
    32: ('SeRelabelPrivilege', "Modify the mandatory integrity level of an object"),
    33: ('SeIncreaseWorkingSetPrivilege', "Allocate more memory for user applications"),
    34: ('SeTimeZonePrivilege', "Adjust the time zone of the computer's internal clock"),
    35: ('SeCreateSymbolicLinkPrivilege', "Required to create a symbolic link"),
    36: ("SeDelegateSessionUserImpersonatePrivilege", "Obtain an impersonation token for another user in the same session."),
}


class Privs(interfaces.plugins.PluginInterface):
    """Lists process token privileges"""

    _version = (1, 0, 0)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._protect_values = None

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        # Since we're calling the plugin, make sure we have the plugin's requirements
        return [requirements.TranslationLayerRequirement(name = 'primary',
                                                         description = 'Memory layer for the kernel',
                                                         architectures = ["Intel32", "Intel64"]),
                requirements.SymbolTableRequirement(name = "nt_symbols", description = "Windows kernel symbols"),
                requirements.ListRequirement(name = 'pid',
                                             description = 'Filter on specific process IDs',
                                             element_type = int,
                                             optional = True),
                requirements.PluginRequirement(name = 'pslist', plugin = pslist.PsList, version = (1, 0, 0)),
                ]

    def _generator(self, procs):

        for task in procs:

            for value, present, enabled, default in task.Token.dereference().cast("_TOKEN").privileges():
                # Skip privileges whose bit positions cannot be
                # translated to a privilege name
                try:
                    name, desc = PRIVILEGE_INFO[int(value)]
                except KeyError:
                    continue

                # Set the attributes
                attributes = []
                if present:
                    attributes.append("Present")
                if enabled:
                    attributes.append("Enabled")
                if default:
                    attributes.append("Default")

                yield (0,
                       [int(task.UniqueProcessId),
                        objects.utility.array_to_string(task.ImageFileName),
                        int(value),
                        str(name),
                        ",".join(attributes),
                        str(desc)])
        
    def run(self):

        filter_func = pslist.PsList.create_pid_filter(self.config.get('pid', None))

        return renderers.TreeGrid([("PID", int), ("Process", str), ("Value", int), ("Privilege", str),
                                   ("Attributes", str), ("Description", str)],
                                  self._generator(
                                      pslist.PsList.list_processes(context = self.context,
                                                                   layer_name = self.config['primary'],
                                                                   symbol_table = self.config['nt_symbols'],
                                                                   filter_func = filter_func)))
