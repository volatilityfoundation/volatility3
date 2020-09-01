# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
# Creator: Aviel Zohar (memoryforensicsanalysis@gmail.com) # Fix vol2 plugin to vol3
import logging
from typing import Callable, List, Generator, Iterable, Dict
import re, ntpath

from volatility.framework import renderers, interfaces, objects, exceptions
from volatility.framework.configuration import requirements
from volatility.framework.objects import utility
from volatility.framework.renderers import format_hints
from volatility.plugins.windows import pslist
from volatility.framework.layers.registry import RegistryFormatException
from volatility.framework.symbols.windows.extensions.registry import RegValueTypes
import volatility.plugins.windows.getservicesids as getservicesids
import volatility.plugins.windows.registry.hivelist as hivelist


vollog = logging.getLogger(__name__)



def find_sid_re(sid_string, sid_re_list) -> str:
    for reg, name in sid_re_list:
        if reg.search(sid_string):
            return name

well_known_sid_re = [
  (re.compile(r'S-1-5-[0-9-]+-500$'), 'Administrator'),
  (re.compile(r'S-1-5-[0-9-]+-501$'), 'Guest'),
  (re.compile(r'S-1-5-[0-9-]+-502$'), 'KRBTGT'),
  (re.compile(r'S-1-5-[0-9-]+-512$'), 'Domain Admins'),
  (re.compile(r'S-1-5-[0-9-]+-513$'), 'Domain Users'),
  (re.compile(r'S-1-5-[0-9-]+-514$'), 'Domain Guests'),
  (re.compile(r'S-1-5-[0-9-]+-515$'), 'Domain Computers'),
  (re.compile(r'S-1-5-[0-9-]+-516$'), 'Domain Controllers'),
  (re.compile(r'S-1-5-[0-9-]+-517$'), 'Cert Publishers'),
  (re.compile(r'S-1-5-[0-9-]+-520$'), 'Group Policy Creator Owners'),
  (re.compile(r'S-1-5-[0-9-]+-533$'), 'RAS and IAS Servers'),
  (re.compile(r'S-1-5-5-[0-9]+-[0-9]+'), 'Logon Session'),
  (re.compile(r'S-1-5-21-[0-9-]+-518$'), 'Schema Admins'),
  (re.compile(r'S-1-5-21-[0-9-]+-519$'), 'Enterprise Admins'),
  (re.compile(r'S-1-5-21-[0-9-]+-553$'), 'RAS Servers'),
  (re.compile(r'S-1-5-21-[0-9-]+-498$'), 'Enterprise Read-Only Domain Controllers'),
  (re.compile(r'S-1-5-21-[0-9-]+-521$'), 'Read-Only Domain Controllers'),
  (re.compile(r'S-1-5-21-[0-9-]+-522$'), 'Cloneable Domain Controllers'),
  (re.compile(r'S-1-5-21-[0-9-]+-525$'), 'Protected Users'),
  (re.compile(r'S-1-5-21-[0-9-]+-553$'), 'Remote Access Services (RAS)'),
]

well_known_sids = {
  'S-1-0': 'Null Authority',
  'S-1-0-0': 'Nobody',
  'S-1-1': 'World Authority',
  'S-1-1-0': 'Everyone',
  'S-1-2': 'Local Authority',
  'S-1-2-0': 'Local (Users with the ability to log in locally)',
  'S-1-2-1': 'Console Logon (Users who are logged onto the physical console)',
  'S-1-3': 'Creator Authority',
  'S-1-3-0': 'Creator Owner',
  'S-1-3-1': 'Creator Group',
  'S-1-3-2': 'Creator Owner Server',
  'S-1-3-3': 'Creator Group Server',
  'S-1-3-4': 'Owner Rights',
  'S-1-4': 'Non-unique Authority',
  'S-1-5': 'NT Authority',
  'S-1-5-1': 'Dialup',
  'S-1-5-2': 'Network',
  'S-1-5-3': 'Batch',
  'S-1-5-4': 'Interactive',
  'S-1-5-6': 'Service',
  'S-1-5-7': 'Anonymous',
  'S-1-5-8': 'Proxy',
  'S-1-5-9': 'Enterprise Domain Controllers',
  'S-1-5-10': 'Principal Self',
  'S-1-5-11': 'Authenticated Users',
  'S-1-5-12': 'Restricted Code',
  'S-1-5-13': 'Terminal Server Users',
  'S-1-5-14': 'Remote Interactive Logon',
  'S-1-5-15': 'This Organization',
  'S-1-5-17': 'This Organization (Used by the default IIS user)',
  'S-1-5-18': 'Local System',
  'S-1-5-19': 'NT Authority',
  'S-1-5-20': 'NT Authority',
  'S-1-5-32-544': 'Administrators',
  'S-1-5-32-545': 'Users',
  'S-1-5-32-546': 'Guests',
  'S-1-5-32-547': 'Power Users',
  'S-1-5-32-548': 'Account Operators',
  'S-1-5-32-549': 'Server Operators',
  'S-1-5-32-550': 'Print Operators',
  'S-1-5-32-551': 'Backup Operators',
  'S-1-5-32-552': 'Replicators',
  'S-1-5-32-554': 'BUILTIN\\Pre-Windows 2000 Compatible Access',
  'S-1-5-32-555': 'BUILTIN\\Remote Desktop Users',
  'S-1-5-32-556': 'BUILTIN\\Network Configuration Operators',
  'S-1-5-32-557': 'BUILTIN\\Incoming Forest Trust Builders',
  'S-1-5-32-558': 'BUILTIN\\Performance Monitor Users',
  'S-1-5-32-559': 'BUILTIN\\Performance Log Users',
  'S-1-5-32-560': 'BUILTIN\\Windows Authorization Access Group',
  'S-1-5-32-561': 'BUILTIN\\Terminal Server License Servers',
  'S-1-5-32-562': 'BUILTIN\\Distributed COM Users',
  'S-1-5-32-568': 'BUILTIN\\IIS IUSRS',
  'S-1-5-32-569': 'Cryptographic Operators',
  'S-1-5-32-573': 'BUILTIN\\Event Log Readers',
  'S-1-5-32-574': 'BUILTIN\\Certificate Service DCOM Access',
  'S-1-5-33': 'Write Restricted',
  'S-1-5-64-10': 'NTLM Authentication',
  'S-1-5-64-14': 'SChannel Authentication',
  'S-1-5-64-21': 'Digest Authentication',
  'S-1-5-80': 'NT Service',
  'S-1-5-86-1544737700-199408000-2549878335-3519669259-381336952': 'WMI (Local Service)',
  'S-1-5-86-615999462-62705297-2911207457-59056572-3668589837': 'WMI (Network Service)',
  'S-1-5-1000': 'Other Organization',
  'S-1-16-0': 'Untrusted Mandatory Level',
  'S-1-16-4096': 'Low Mandatory Level',
  'S-1-16-8192': 'Medium Mandatory Level',
  'S-1-16-8448': 'Medium Plus Mandatory Level',
  'S-1-16-12288': 'High Mandatory Level',
  'S-1-16-16384': 'System Mandatory Level',
  'S-1-16-20480': 'Protected Process Mandatory Level',
  'S-1-16-28672': 'Secure Process Mandatory Level',
  'S-1-5-21-0-0-0-496': 'Compounded Authentication',
  'S-1-5-21-0-0-0-497': 'Claims Valid',
  'S-1-5-32-575': 'RDS Remote Application Services',
  'S-1-5-32-576': 'RDS Endpoint Servers',
  'S-1-5-32-577': 'RDS Management Servers',
  'S-1-5-32-578': 'Hyper-V Admins',
  'S-1-5-32-579': 'Access Control Assistance Ops',
  'S-1-5-32-580': 'Remote Management Users',
  'S-1-5-65-1': 'This Organization Certificate (Kerberos PAC)',
  'S-1-5-84-0-0-0-0-0': 'Usermode Drivers',
  'S-1-5-113': 'Local Account',
  'S-1-5-114': 'Local Account (Member of Administrators)',
  'S-1-5-1000': 'Other Organization',
  'S-1-15-2-1': 'Application Package Context',
  'S-1-18-1': 'Authentication Authority Asserted Identity',
  'S-1-18-2': 'Service Asserted Identity',
}


class GetSIDs(interfaces.plugins.PluginInterface):
    """Print the SIDs owning each process"""

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

    def lookup_user_sids(self) -> Dict[str, str]:
        """
        Enumerate the registry for all the users.

        Returns:
            An dictionary of {sid: user name}
        """

        key = "Microsoft\\Windows NT\\CurrentVersion\\ProfileList"
        val = "ProfileImagePath"

        sids = {}
        for hive in hivelist.HiveList.list_hives(context = self.context,
                                 base_config_path = self.config_path,
                                 layer_name = self.config['primary'],
                                 symbol_table = self.config['nt_symbols'],
                                 hive_offsets = None):
        
            try:
                for subkey in hive.get_key(key).get_subkeys():
                    sid = str(subkey.get_name())
                    path = ""
                    for node in subkey.get_values():
                        try:
                            value_node_name = node.get_name() or "(Default)"
                        except (exceptions.InvalidAddressException, RegistryFormatException) as excp:
                            continue
                        try:
                            value_data = node.decode_data()
                            if isinstance(value_data, int):
                                value_data = format_hints.MultiTypeData(value_data, encoding = 'utf-8')
                            elif RegValueTypes.get(node.Type) == RegValueTypes.REG_BINARY:
                                value_data = format_hints.MultiTypeData(value_data, show_hex = True)
                            elif RegValueTypes.get(node.Type) == RegValueTypes.REG_MULTI_SZ:
                                value_data = format_hints.MultiTypeData(value_data,
                                                                        encoding = 'utf-16-le',
                                                                        split_nulls = True)
                            else:
                                value_data = format_hints.MultiTypeData(value_data, encoding = 'utf-16-le')
                            if value_node_name == val:
                                path = str(value_data).replace('\\x00', '')[:-1]
                                user = ntpath.basename(path)
                                sids[sid] = user
                        except (ValueError, exceptions.InvalidAddressException, RegistryFormatException) as excp:
                            continue
            except KeyError:
                continue

        return sids

    def _generator(self, procs):

        user_sids = self.lookup_user_sids()

        for task in procs:
            token = task.Token.dereference().cast("_TOKEN")

            if not token:
                yield (0, [int(task.UniqueProcessId),
                                 str(task.ImageFileName),
                                 "Token unreadable",
                                 ""])
                continue

            for sid_string in token.get_sids():
                if sid_string in well_known_sids:
                    sid_name = well_known_sids[sid_string]
                elif sid_string in getservicesids.servicesids:
                    sid_name = getservicesids.servicesids[sid_string]
                elif sid_string in user_sids:
                    sid_name = user_sids[sid_string]
                else:
                    sid_name_re = find_sid_re(sid_string, well_known_sid_re)
                    if sid_name_re:
                        sid_name = sid_name_re
                    else:
                        sid_name = ""

                yield (0, [int(task.UniqueProcessId),
                                 objects.utility.array_to_string(task.ImageFileName),
                                 str(sid_string),
                                 str(sid_name)])

        
    def run(self):

        filter_func = pslist.PsList.create_pid_filter(self.config.get('pid', None))

        return renderers.TreeGrid([("PID", int),("Process", str),("SID", str),("Name", str)],
                                  self._generator(pslist.PsList.list_processes(context = self.context,
                                                                         layer_name = self.config['primary'],
                                                                         symbol_table = self.config['nt_symbols'],
                                                                         filter_func = filter_func)))
