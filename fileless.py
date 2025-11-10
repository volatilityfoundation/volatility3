import logging
import re
import struct
from typing import List, Dict, Tuple, Set
from volatility3.framework import interfaces, renderers, exceptions
from volatility3.framework.configuration import requirements
from volatility3.framework.objects import utility
from volatility3.plugins.windows import pslist, vadinfo, handles

vollog = logging.getLogger(__name__)

class FilelessMalwareHunter(interfaces.plugins.PluginInterface):
    """Advanced fileless malware and in-memory threat detection for Windows memory dumps."""
    _required_framework_version = (2, 0, 0)
    _version = (2, 0, 0)
    
    # Enhanced PowerShell patterns
    POWERSHELL_PATTERNS = {
        'encoded_command': (rb'-e[ncodedcommand]*\s+[A-Za-z0-9+/=]{50,}', 'Critical'),
        'invoke_expression': (rb'(?i)(iex|invoke-expression)', 'High'),
        'download_string': (rb'(?i)(downloadstring|downloadfile|downloaddata)', 'Critical'),
        'invoke_webrequest': (rb'(?i)(invoke-webrequest|invoke-restmethod)', 'High'),
        'net_webclient': (rb'(?i)system\.net\.webclient', 'High'),
        'hidden_window': (rb'(?i)-windowstyle\s+hidden', 'High'),
        'bypass_execution': (rb'(?i)-executionpolicy\s+bypass', 'High'),
        'encoded_script': (rb'(?i)frombase64string', 'High'),
        'reflection_assembly': (rb'(?i)\[reflection\.assembly\]::load', 'Critical'),
        'invoke_mimikatz': (rb'(?i)invoke-mimikatz', 'Critical'),
        'invoke_shellcode': (rb'(?i)invoke-shellcode', 'Critical'),
        'compressed_script': (rb'(?i)io\.compression\.gzipstream', 'Medium'),
        'obfuscation': (rb'(?i)(\^|\`|"|\+){10,}', 'High'),
        'memory_stream': (rb'(?i)system\.io\.memorystream', 'Medium'),
        'process_start': (rb'(?i)system\.diagnostics\.process]::start', 'High'),
        'amsi_bypass': (rb'(?i)(amsiutils|amsiinitfailed|amsi\.dll)', 'Critical'),
        'empire_framework': (rb'(?i)(invoke-empire|get-empire)', 'Critical'),
        'cobalt_strike': (rb'(?i)(invoke-beacon|invoke-dllinjection)', 'Critical'),
        'metasploit': (rb'(?i)(invoke-meterpreter|invoke-payload)', 'Critical'),
        'psattack': (rb'(?i)psattack', 'Critical'),
        'nishang': (rb'(?i)invoke-powershelltcp', 'Critical'),
    }
    
    # Credential theft patterns
    CREDENTIAL_PATTERNS = {
        'mimikatz_signature': (rb'(?i)(gentilkiwi|benjamin delpy|sekurlsa|lsadump)', 'Critical'),
        'lsass_dump': (rb'(?i)(lsass\.exe|lsass\.dmp|procdump.*lsass)', 'Critical'),
        'sam_dump': (rb'(?i)(reg.*save.*sam|reg.*save.*system)', 'Critical'),
        'credential_manager': (rb'(?i)vaultcmd', 'High'),
        'ntds_dit': (rb'(?i)ntds\.dit', 'Critical'),
        'cached_credentials': (rb'(?i)mscash', 'High'),
        'kerberos_ticket': (rb'(?i)(kirbi|invoke-kerberoast)', 'Critical'),
        'dpapi': (rb'(?i)dpapi', 'High'),
        'laZagne': (rb'(?i)lazagne', 'Critical'),
        'password_filter': (rb'(?i)passwordchangenotify', 'Critical'),
    }
    
    # WMI attack patterns
    WMI_PATTERNS = {
        'wmi_process_create': (rb'(?i)win32_process.*create', 'High'),
        'wmi_event_consumer': (rb'(?i)commandlineeventconsumer', 'Critical'),
        'wmi_persistence': (rb'(?i)__eventfilter', 'Critical'),
        'wmi_lateral_movement': (rb'(?i)win32_scheduledjob', 'High'),
        'wmi_exec': (rb'(?i)wmiexec', 'High'),
    }
    
    # Persistence mechanisms
    PERSISTENCE_PATTERNS = {
        'registry_run': (rb'(?i)(software\\microsoft\\windows\\currentversion\\run)', 'High'),
        'startup_folder': (rb'(?i)(startup|start menu\\programs\\startup)', 'High'),
        'scheduled_task': (rb'(?i)(schtasks.*create|register-scheduledtask)', 'High'),
        'service_creation': (rb'(?i)(sc.*create|new-service)', 'High'),
        'dll_hijacking': (rb'(?i)(dll.*order|dll.*search)', 'Medium'),
        'winlogon': (rb'(?i)software\\microsoft\\windows nt\\currentversion\\winlogon', 'High'),
        'image_file_execution': (rb'(?i)image file execution options', 'High'),
        'app_init': (rb'(?i)appinit_dlls', 'High'),
        'bits_jobs': (rb'(?i)start-bitstransfer', 'Medium'),
    }
    
    # Lateral movement patterns
    LATERAL_MOVEMENT_PATTERNS = {
        'psexec': (rb'(?i)psexe(c|csvc)', 'Critical'),
        'remote_exec': (rb'(?i)(winrs|wmic.*node)', 'High'),
        'smb_exec': (rb'(?i)(\\\\.*\\admin\$|\\\\.*\\c\$|\\\\.*\\ipc\$)', 'High'),
        'rdp_usage': (rb'(?i)(mstsc|terminal.*server)', 'Medium'),
        'pass_the_hash': (rb'(?i)(sekurlsa::pth|invoke-pth)', 'Critical'),
        'pass_the_ticket': (rb'(?i)(kerberos::ptt|invoke-mimikatz.*ticket)', 'Critical'),
        'dcom_exec': (rb'(?i)mmc20\.application', 'High'),
        'wmi_exec_remote': (rb'(?i)invoke-wmimethod.*-computer', 'High'),
    }
    
    # Defense evasion patterns  
    EVASION_PATTERNS = {
        'disable_defender': (rb'(?i)(set-mppreference.*-disable|add-mppreference.*-exclusion)', 'Critical'),
        'clear_logs': (rb'(?i)(wevtutil.*cl|clear-eventlog)', 'Critical'),
        'timestomp': (rb'(?i)timestomp', 'High'),
        'sandbox_detection': (rb'(?i)(check.*vm|detect.*sandbox)', 'Medium'),
        'disable_firewall': (rb'(?i)(netsh.*firewall.*off|set-netfirewallprofile)', 'High'),
        'disable_uac': (rb'(?i)enablelua.*0', 'High'),
        'process_masquerading': (rb'(?i)(svchost\.exe.*-k|rundll32.*,#1)', 'High'),
        'rootkit': (rb'(?i)(zwsetsysteminformation|ntquerysysteminformation)', 'Critical'),
    }
    
    # Malware families signatures
    MALWARE_FAMILIES = {
        'emotet': (rb'(?i)(emotet|epoch[1-5])', 'Critical'),
        'trickbot': (rb'(?i)trickbot', 'Critical'),
        'ryuk': (rb'(?i)(ryuk|hermes)', 'Critical'),
        'conti': (rb'(?i)conti', 'Critical'),
        'lockbit': (rb'(?i)lockbit', 'Critical'),
        'qakbot': (rb'(?i)(qakbot|qbot)', 'Critical'),
        'dridex': (rb'(?i)dridex', 'Critical'),
        'icedid': (rb'(?i)icedid', 'Critical'),
        'bumblebee': (rb'(?i)bumblebee', 'Critical'),
    }
    
    # Cryptocurrency Miners signatures
    CRYPTO_MINER_SIGNATURES = {
        # Popular Mining Software
        'xmrig': (rb'(?i)(xmrig|monero.*miner)', 'Critical'),
        'xmrig_config': (rb'(?i)(donate-level|algo.*randomx|pool.*xmr)', 'Critical'),
        'claymore': (rb'(?i)(claymore|ethminer)', 'Critical'),
        'phoenixminer': (rb'(?i)phoenixminer', 'Critical'),
        'cgminer': (rb'(?i)cgminer', 'Critical'),
        'bfgminer': (rb'(?i)bfgminer', 'Critical'),
        'nicehash': (rb'(?i)(nicehash|nhminer)', 'Critical'),
        'minergate': (rb'(?i)minergate', 'Critical'),
        'ccminer': (rb'(?i)ccminer', 'Critical'),
        'cpuminer': (rb'(?i)(cpuminer|minerd)', 'Critical'),
        'ethminer': (rb'(?i)ethminer', 'Critical'),
        'ewbf': (rb'(?i)ewbf', 'Critical'),
        'bminer': (rb'(?i)bminer', 'Critical'),
        'gminer': (rb'(?i)gminer', 'Critical'),
        'lolminer': (rb'(?i)lolminer', 'Critical'),
        'nbminer': (rb'(?i)nbminer', 'Critical'),
        'trex_miner': (rb'(?i)(t-rex|trex.*miner)', 'Critical'),
        'teamredminer': (rb'(?i)teamredminer', 'Critical'),
        
        # Mining Pools
        'mining_pool_stratum': (rb'(?i)(stratum\+tcp|stratum\+ssl)', 'High'),
        'monero_pool': (rb'(?i)(xmr.*pool|moneroocean|supportxmr|minexmr)', 'High'),
        'ethereum_pool': (rb'(?i)(ethermine|nanopool|f2pool.*eth)', 'High'),
        'bitcoin_pool': (rb'(?i)(slushpool|antpool|btc\.com)', 'High'),
        'mining_pool_url': (rb'(?i)(pool\..*\..*:3333|pool\..*\..*:4444|pool\..*\..*:5555)', 'High'),
        
        # Mining Algorithms
        'cryptonight': (rb'(?i)(cryptonight|cryptonight-lite|cn/r)', 'High'),
        'randomx': (rb'(?i)(randomx|rx/0)', 'High'),
        'ethash': (rb'(?i)ethash', 'High'),
        'kawpow': (rb'(?i)kawpow', 'High'),
        'equihash': (rb'(?i)equihash', 'High'),
        'scrypt': (rb'(?i)(scrypt|litecoin)', 'High'),
        
        # Cryptocurrency Wallets in Memory
        'monero_wallet': (rb'(?i)(4[0-9AB][1-9A-HJ-NP-Za-km-z]{93})', 'Critical'),
        'bitcoin_wallet': (rb'(?i)([13][a-km-zA-HJ-NP-Z1-9]{25,34})', 'High'),
        'ethereum_wallet': (rb'(?i)(0x[a-fA-F0-9]{40})', 'High'),
        
        # Mining Configuration
        'mining_config': (rb'(?i)(mining.*config|config.*pool|worker.*name)', 'Medium'),
        'hashrate': (rb'(?i)(hashrate|h/s|kh/s|mh/s)', 'Medium'),
        'difficulty': (rb'(?i)(difficulty.*target|share.*difficulty)', 'Medium'),
        
        # Malicious Miners
        'coinhive': (rb'(?i)(coinhive|coin-hive)', 'Critical'),
        'cryptoloot': (rb'(?i)cryptoloot', 'Critical'),
        'jsecoin': (rb'(?i)jsecoin', 'Critical'),
        'webminerpool': (rb'(?i)webminerpool', 'Critical'),
        'mineralt': (rb'(?i)mineralt', 'Critical'),
        'authedmine': (rb'(?i)authedmine', 'Critical'),
        'coinimp': (rb'(?i)coinimp', 'Critical'),
        'crypto_loot': (rb'(?i)crypto-loot', 'Critical'),
        'deepminer': (rb'(?i)deepminer', 'Critical'),
        'gridcash': (rb'(?i)gridcash', 'Critical'),
        
        # Hidden Miners
        'xmr_stak': (rb'(?i)(xmr-stak|xmrstak)', 'Critical'),
        'srbminer': (rb'(?i)srbminer', 'Critical'),
        'wildrig': (rb'(?i)wildrig', 'Critical'),
        'kawpowminer': (rb'(?i)kawpowminer', 'Critical'),
        
        # Browser-based Mining
        'browser_mining': (rb'(?i)(cryptonight\.wasm|mining\.js|miner\.js)', 'High'),
        'web_assembly_mining': (rb'(?i)(wasm.*crypto|crypto.*wasm)', 'High'),
        
        # Mining Commands
        'mining_command': (rb'(?i)(--algo|--pool|--user|--pass.*x|--donate-level)', 'High'),
        'gpu_mining': (rb'(?i)(--cuda|--opencl|--gpu)', 'Medium'),
        'cpu_mining': (rb'(?i)(--threads|--cpu-priority)', 'Medium'),
        
        # Stealth Mining Indicators
        'process_hiding': (rb'(?i)(hide.*window|invisible.*mode|stealth.*mode)', 'High'),
        'mining_rootkit': (rb'(?i)(rootkit.*miner|miner.*rootkit)', 'Critical'),
        'persistence_mining': (rb'(?i)(scheduled.*miner|startup.*miner)', 'High'),
    }
    
    # Mining Process Names
    MINER_PROCESS_NAMES = {
        'xmrig.exe': 'XMRig Monero Miner',
        'xmrig-cuda.exe': 'XMRig CUDA Miner',
        'xmrig-nvidia.exe': 'XMRig NVIDIA Miner',
        'xmrig-amd.exe': 'XMRig AMD Miner',
        'claymore.exe': 'Claymore Miner',
        'ethminer.exe': 'Ethereum Miner',
        'phoenixminer.exe': 'Phoenix Miner',
        'cgminer.exe': 'CGMiner',
        'bfgminer.exe': 'BFGMiner',
        'nheqminer.exe': 'NiceHash Miner',
        'ccminer.exe': 'CCMiner',
        'minerd.exe': 'CPU Miner',
        'cpuminer.exe': 'CPU Miner',
        'minergate.exe': 'MinerGate',
        'nicehash.exe': 'NiceHash',
        'gminer.exe': 'GMiner',
        'lolminer.exe': 'LolMiner',
        'nbminer.exe': 'NBMiner',
        't-rex.exe': 'T-Rex Miner',
        'teamredminer.exe': 'Team Red Miner',
        'srbminer.exe': 'SRBMiner',
        'wildrig.exe': 'WildRig Miner',
        'bminer.exe': 'BMiner',
        'ewbf.exe': 'EWBF Miner',
        'excavator.exe': 'NiceHash Excavator',
        'xmr-stak.exe': 'XMR-Stak',
        'xmr-stack-cpu.exe': 'XMR-Stak CPU',
        'xmr-stack-amd.exe': 'XMR-Stak AMD',
        'xmr-stack-nvidia.exe': 'XMR-Stak NVIDIA',
    }
    
    # Remote Access Trojans (RATs) signatures
    RAT_SIGNATURES = {
        # njRAT - Multiple signatures for better detection
        'njrat': (rb'(?i)(njrat|bladabindi)', 'Critical'),
        'njrat_mutex': (rb'(?i)(njrat.*mutex|bladabindi.*mutex)', 'Critical'),
        'njrat_registry': (rb'(?i)(njrat.*registry|software\\microsoft\\windows\\currentversion\\run.*njrat)', 'Critical'),
        'njrat_c2': (rb'(?i)(njrat.*server|njrat.*c2|njrat.*panel)', 'Critical'),
        'njrat_plugin': (rb'(?i)(plugin.*njrat|njrat.*plugin)', 'Critical'),
        'njrat_strings': (rb'(?i)(njworm|njspy|njlogger)', 'Critical'),
        'njrat_commands': (rb'(?i)(ll|rn|inv|ret|CAP|un|up|RG|kl)', 'High'),
        'njrat_base64': (rb'(?i)(am5yYXQ|bmpy|Ymxh)', 'High'),  # njrat base64 encoded
        
        # DarkComet - Enhanced detection
        'darkcomet': (rb'(?i)(darkcomet|dc_mutexrat)', 'Critical'),
        'darkcomet_mutex': (rb'(?i)(dc_mutex|dcmutex|darkcomet.*mutex)', 'Critical'),
        'darkcomet_registry': (rb'(?i)(darkcomet.*registry|dcregistry)', 'Critical'),
        'darkcomet_rat': (rb'(?i)(dcrat|darkcomet.*rat)', 'Critical'),
        'darkcomet_version': (rb'(?i)(darkcomet.*5\.[0-9]|dc.*5\.[0-9])', 'Critical'),
        'darkcomet_keylogger': (rb'(?i)(dc.*keylog|darkcomet.*keylog)', 'Critical'),
        'darkcomet_stub': (rb'(?i)(stub.*darkcomet|dc.*stub)', 'Critical'),
        'darkcomet_strings': (rb'(?i)(DCRATKILL|DCRATID|GENCODE)', 'Critical'),
        'darkcomet_config': (rb'(?i)(darkcomet.*config|dcconfig)', 'High'),
        
        # Quasar RAT - Comprehensive signatures
        'quasar': (rb'(?i)(quasar.*rat|xrat)', 'Critical'),
        'quasar_namespace': (rb'(?i)(xrat\..*|quasar\.)', 'Critical'),
        'quasar_mutex': (rb'(?i)(quasar.*mutex|xrat.*mutex)', 'Critical'),
        'quasar_client': (rb'(?i)(quasar.*client|quasarclient)', 'Critical'),
        'quasar_server': (rb'(?i)(quasar.*server|quasarserver)', 'Critical'),
        'quasar_assembly': (rb'(?i)(quasar\..*assembly)', 'Critical'),
        'quasar_keylogger': (rb'(?i)(quasar.*keylogger)', 'Critical'),
        'quasar_commands': (rb'(?i)(getpasswords|getserverpassword|remotedesktop)', 'High'),
        'quasar_config': (rb'(?i)(quasar.*settings|quasar.*config)', 'High'),
        'quasar_communication': (rb'(?i)(quasar.*networking|xrat.*net)', 'High'),
        
        # Popular RATs
        'nanocore': (rb'(?i)(nanocore|nanobot)', 'Critical'),
        'remcos': (rb'(?i)(remcos|remcosrat)', 'Critical'),
        'asyncrat': (rb'(?i)(asyncrat|async.*rat)', 'Critical'),
        'netwire': (rb'(?i)(netwire|netwiredrc)', 'Critical'),
        'poisonivy': (rb'(?i)(poison.*ivy|pivy)', 'Critical'),
        'blackshades': (rb'(?i)(blackshades|bsnet)', 'Critical'),
        'cybergate': (rb'(?i)cybergate', 'Critical'),
        
        # Advanced RATs
        'cobaltstrike': (rb'(?i)(beacon.*dll|cobaltstrike|malleable)', 'Critical'),
        'meterpreter': (rb'(?i)(meterpreter|msf.*payload)', 'Critical'),
        'empire': (rb'(?i)(powershell.*empire|invoke.*empire)', 'Critical'),
        'pupy': (rb'(?i)pupy.*rat', 'Critical'),
        'covenant': (rb'(?i)(covenant|grunt)', 'Critical'),
        
        # Commercial/Government RATs
        'gh0st': (rb'(?i)(gh0st|gh0strat)', 'Critical'),
        'plugx': (rb'(?i)(plugx|korplug)', 'Critical'),
        'sakula': (rb'(?i)sakula', 'Critical'),
        'winnti': (rb'(?i)winnti', 'Critical'),
        'shadowpad': (rb'(?i)shadowpad', 'Critical'),
        'covenant_rat': (rb'(?i)covenant', 'Critical'),
        
        # Mobile/Cross-platform RATs
        'androrat': (rb'(?i)androrat', 'Critical'),
        'omnirat': (rb'(?i)omnirat', 'Critical'),
        'spynote': (rb'(?i)spynote', 'Critical'),
        
        # Banking/Stealer RATs
        'zeus': (rb'(?i)(zeus|zbot)', 'Critical'),
        'carberp': (rb'(?i)carberp', 'Critical'),
        'tinba': (rb'(?i)tinba', 'Critical'),
        'ursnif': (rb'(?i)(ursnif|gozi)', 'Critical'),
        'formbook': (rb'(?i)formbook', 'Critical'),
        'agent_tesla': (rb'(?i)(agenttesla|agent.*tesla)', 'Critical'),
        'lokibot': (rb'(?i)(lokibot|loki.*pwd)', 'Critical'),
        'azorult': (rb'(?i)azorult', 'Critical'),
        'raccoon': (rb'(?i)(raccoon.*stealer)', 'Critical'),
        
        # APT-related RATs
        'htran': (rb'(?i)htran', 'Critical'),
        'reaver': (rb'(?i)reaver', 'Critical'),
        'cobalt_kitty': (rb'(?i)cobalt.*kitty', 'Critical'),
        'darkhotel': (rb'(?i)darkhotel', 'Critical'),
        'apt1_rat': (rb'(?i)(seasalt|rockboot)', 'Critical'),
        
        # Open Source RATs
        'orcus': (rb'(?i)orcus.*rat', 'Critical'),
        'revenge_rat': (rb'(?i)revenge.*rat', 'Critical'),
        'havex': (rb'(?i)havex', 'Critical'),
        'adwind': (rb'(?i)(adwind|jrat|sockrat)', 'Critical'),
        'unrecom': (rb'(?i)unrecom', 'Critical'),
        'njw0rm': (rb'(?i)njw0rm', 'Critical'),
        'lime_rat': (rb'(?i)lime.*rat', 'Critical'),
        'xpertrat': (rb'(?i)xpert.*rat', 'Critical'),
        
        # Modern RATs (2020+)
        'sliver': (rb'(?i)sliver', 'Critical'),
        'brute_ratel': (rb'(?i)(brute.*ratel|badger)', 'Critical'),
        'mythic': (rb'(?i)(mythic|apollo.*agent)', 'Critical'),
        'havoc': (rb'(?i)havoc.*c2', 'Critical'),
        'villain': (rb'(?i)villain.*c2', 'Critical'),
        
        # Backdoors
        'backdoor_factory': (rb'(?i)(backdoor.*factory|bdf)', 'Critical'),
        'bifrost': (rb'(?i)bifrost', 'Critical'),
        'turla': (rb'(?i)(turla|uroburos)', 'Critical'),
        'derusbi': (rb'(?i)derusbi', 'Critical'),
        
        # Web Shells
        'china_chopper': (rb'(?i)(china.*chopper|caidao)', 'Critical'),
        'aspxspy': (rb'(?i)aspxspy', 'Critical'),
        'webshell': (rb'(?i)(eval.*request|execute.*request)', 'High'),
        
        # Commodity RATs
        'warzone': (rb'(?i)(warzone.*rat|ave.*maria)', 'Critical'),
        'dcrat': (rb'(?i)dcrat', 'Critical'),
        'parallax': (rb'(?i)parallax.*rat', 'Critical'),
        'xworm': (rb'(?i)xworm', 'Critical'),
        'plasma': (rb'(?i)plasma.*rat', 'Critical'),
    }
    
    # Network indicators
    NETWORK_PATTERNS = {
        'c2_beacon': (rb'(?i)(beacon|heartbeat|checkin)', 'High'),
        'reverse_shell': (rb'(?i)(reverse.*shell|bind.*shell)', 'Critical'),
        'tunnel': (rb'(?i)(chisel|ngrok|serveo)', 'High'),
        'exfiltration': (rb'(?i)(exfil|upload.*data)', 'Critical'),
    }
    
    # Living off the land binaries with enhanced detection
    LOLBINS = {
        'powershell.exe': ('PowerShell', 'T1059.001'),
        'pwsh.exe': ('PowerShell Core', 'T1059.001'),
        'powershell_ise.exe': ('PowerShell ISE', 'T1059.001'),
        'cmd.exe': ('Command Prompt', 'T1059.003'),
        'wmic.exe': ('WMI Command', 'T1047'),
        'mshta.exe': ('HTML Application', 'T1218.005'),
        'regsvr32.exe': ('Register Server', 'T1218.010'),
        'rundll32.exe': ('Run DLL', 'T1218.011'),
        'cscript.exe': ('VBScript Engine', 'T1059.005'),
        'wscript.exe': ('Windows Script Host', 'T1059.005'),
        'certutil.exe': ('Certificate Utility', 'T1140'),
        'bitsadmin.exe': ('BITS Admin', 'T1197'),
        'msiexec.exe': ('Windows Installer', 'T1218.007'),
        'regasm.exe': ('.NET Assembly Registration', 'T1218.009'),
        'regsvcs.exe': ('.NET Services', 'T1218.009'),
        'installutil.exe': ('.NET Installer', 'T1218.004'),
        'msbuild.exe': ('MSBuild', 'T1127.001'),
        'cmstp.exe': ('Connection Manager', 'T1218.003'),
        'odbcconf.exe': ('ODBC Config', 'T1218.008'),
        'schtasks.exe': ('Task Scheduler', 'T1053.005'),
        'at.exe': ('AT Command', 'T1053.002'),
        'sc.exe': ('Service Control', 'T1543.003'),
        'net.exe': ('Net Command', 'T1087'),
        'net1.exe': ('Net Command', 'T1087'),
        'whoami.exe': ('User Identity', 'T1033'),
        'systeminfo.exe': ('System Info', 'T1082'),
        'tasklist.exe': ('Task List', 'T1057'),
        'netstat.exe': ('Network Stats', 'T1049'),
        'ipconfig.exe': ('IP Config', 'T1016'),
        'arp.exe': ('ARP', 'T1018'),
        'route.exe': ('Route', 'T1016'),
        'netsh.exe': ('Network Shell', 'T1562.004'),
        'forfiles.exe': ('ForFiles', 'T1222'),
        'pcalua.exe': ('Program Compatibility', 'T1218'),
        'mavinject.exe': ('Mavinject', 'T1218'),
        'control.exe': ('Control Panel', 'T1218'),
        'msdt.exe': ('Microsoft Diagnostics', 'T1218'),
    }
    
    # Suspicious DLLs
    SUSPICIOUS_DLLS = [
        'sbiedll.dll', 'dbghelp.dll', 'api_log.dll', 'vmGuestLib.dll',
        'vboxmrxnp.dll', 'VBoxHook.dll', 'prltools.dll', 'inject.dll',
        'reflective.dll', 'magic.dll', 'hook.dll'
    ]
    
    # Code cave indicators (RWX memory)
    CODE_CAVE_SIZE_THRESHOLD = 4096  # Increased from 1024 to reduce false positives
    
    # Minimum match confidence
    MIN_PATTERN_LENGTH = 20  # Minimum bytes to match for detection
    
    # Whitelist for known legitimate processes
    LEGITIMATE_PROCESSES = [
        'system', 'smss.exe', 'csrss.exe', 'wininit.exe', 'services.exe',
        'lsass.exe', 'svchost.exe', 'winlogon.exe', 'dwm.exe', 'explorer.exe',
        'taskhost.exe', 'taskhostw.exe', 'spoolsv.exe', 'sihost.exe'
    ]
    
    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Windows kernel module",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.IntRequirement(
                name="pid",
                description="Filter by specific process ID",
                optional=True,
                default=None
            ),
            requirements.BooleanRequirement(
                name="verbose",
                description="Enable verbose output with additional details",
                optional=True,
                default=False
            ),
            requirements.IntRequirement(
                name="min-severity",
                description="Minimum severity level (1=Low, 2=Medium, 3=High, 4=Critical)",
                optional=True,
                default=1
            ),
        ]
    
    def _is_false_positive(self, proc_name: str, detection_type: str, indicator: str) -> bool:
        """Check if detection is likely a false positive."""
        
        # Skip detections in core system processes for certain types
        if proc_name in self.LEGITIMATE_PROCESSES:
            # Allow only critical detections in system processes
            if detection_type in ['LOLBin Abuse', '.NET Injection', 'Orphan Process']:
                return True
        
        # Filter out common false positives
        false_positive_patterns = [
            # Common legitimate .NET usage
            (detection_type == '.NET Injection' and proc_name in ['explorer.exe', 'taskhost.exe', 'taskhostw.exe']),
            
            # Legitimate svchost instances
            (detection_type == 'Orphan Process' and proc_name == 'svchost.exe'),
            
            # System processes with low thread counts
            (detection_type == 'Thread Injection' and proc_name in self.LEGITIMATE_PROCESSES),
        ]
        
        return any(false_positive_patterns)
    
    def _validate_detection(self, data: bytes, pattern: bytes, min_length: int = 20) -> bool:
        """Validate that pattern match is substantial enough."""
        match = re.search(pattern, data)
        if match:
            matched_text = match.group(0)
            # Ensure matched text is substantial
            return len(matched_text) >= min_length
        return False
        """Convert severity string to numeric value."""
        severity_map = {'Low': 1, 'Medium': 2, 'High': 3, 'Critical': 4}
        return severity_map.get(severity, 1)
    
    def _scan_process_memory(self, proc, proc_name: str, proc_pid: int) -> List[Dict]:
        """Scan process memory for suspicious patterns with enhanced detection."""
        detections = []
        
        try:
            proc_layer_name = proc.add_process_layer()
            proc_layer = self.context.layers[proc_layer_name]
            
            # Scan VADs for suspicious content
            for vad in proc.get_vad_root().traverse():
                try:
                    protection = vad.get_protection()
                    start = vad.get_start()
                    end = vad.get_end()
                    size = end - start
                    vad_file = vad.get_file_name()
                    
                    # Check for RWX memory (code caves)
                    if 'EXECUTE_READWRITE' in protection or ('EXECUTE' in protection and 'WRITE' in protection):
                        if size >= self.CODE_CAVE_SIZE_THRESHOLD:
                            # Additional validation - check if memory contains actual code
                            try:
                                data_sample = proc_layer.read(start, min(size, 512))
                                # Check for code-like patterns (not just zeros)
                                non_zero_count = sum(1 for b in data_sample if b != 0)
                                if non_zero_count > len(data_sample) * 0.1:  # At least 10% non-zero
                                    detections.append({
                                        'type': 'Code Cave (RWX)',
                                        'process': proc_name,
                                        'pid': proc_pid,
                                        'indicator': f'RWX memory region ({size} bytes)',
                                        'severity': 'Critical',
                                        'address': f'{hex(start)}-{hex(end)}',
                                        'protection': protection,
                                        'technique': 'T1055.011 - Extra Window Memory Injection'
                                    })
                            except:
                                pass
                    
                    # Focus on executable regions
                    if 'EXECUTE' in protection:
                        try:
                            data = proc_layer.read(start, min(size, 2 * 1024 * 1024))  # Read up to 2MB
                            
                            # Check for PowerShell patterns
                            for pattern_name, (pattern, severity) in self.POWERSHELL_PATTERNS.items():
                                if self._validate_detection(data, pattern, 15):
                                    detection = {
                                        'type': 'PowerShell Script',
                                        'process': proc_name,
                                        'pid': proc_pid,
                                        'indicator': pattern_name.replace('_', ' ').title(),
                                        'severity': severity,
                                        'address': hex(start),
                                        'protection': protection,
                                        'technique': 'T1059.001 - PowerShell'
                                    }
                                    if not self._is_false_positive(proc_name, 'PowerShell Script', pattern_name):
                                        detections.append(detection)
                                    break
                            
                            # Check for credential theft patterns
                            for pattern_name, (pattern, severity) in self.CREDENTIAL_PATTERNS.items():
                                if self._validate_detection(data, pattern, 10):
                                    detections.append({
                                        'type': 'Credential Theft',
                                        'process': proc_name,
                                        'pid': proc_pid,
                                        'indicator': pattern_name.replace('_', ' ').title(),
                                        'severity': severity,
                                        'address': hex(start),
                                        'protection': protection,
                                        'technique': 'T1003 - OS Credential Dumping'
                                    })
                                    break
                            
                            # Check for WMI patterns
                            for pattern_name, (pattern, severity) in self.WMI_PATTERNS.items():
                                if re.search(pattern, data):
                                    detections.append({
                                        'type': 'WMI Execution',
                                        'process': proc_name,
                                        'pid': proc_pid,
                                        'indicator': pattern_name.replace('_', ' ').title(),
                                        'severity': severity,
                                        'address': hex(start),
                                        'protection': protection,
                                        'technique': 'T1047 - Windows Management Instrumentation'
                                    })
                                    break
                            
                            # Check for persistence patterns
                            for pattern_name, (pattern, severity) in self.PERSISTENCE_PATTERNS.items():
                                if re.search(pattern, data):
                                    detections.append({
                                        'type': 'Persistence Mechanism',
                                        'process': proc_name,
                                        'pid': proc_pid,
                                        'indicator': pattern_name.replace('_', ' ').title(),
                                        'severity': severity,
                                        'address': hex(start),
                                        'protection': protection,
                                        'technique': 'T1547 - Boot/Logon Autostart'
                                    })
                                    break
                            
                            # Check for lateral movement patterns
                            for pattern_name, (pattern, severity) in self.LATERAL_MOVEMENT_PATTERNS.items():
                                if re.search(pattern, data):
                                    detections.append({
                                        'type': 'Lateral Movement',
                                        'process': proc_name,
                                        'pid': proc_pid,
                                        'indicator': pattern_name.replace('_', ' ').title(),
                                        'severity': severity,
                                        'address': hex(start),
                                        'protection': protection,
                                        'technique': 'T1021 - Remote Services'
                                    })
                                    break
                            
                            # Check for defense evasion patterns
                            for pattern_name, (pattern, severity) in self.EVASION_PATTERNS.items():
                                if re.search(pattern, data):
                                    detections.append({
                                        'type': 'Defense Evasion',
                                        'process': proc_name,
                                        'pid': proc_pid,
                                        'indicator': pattern_name.replace('_', ' ').title(),
                                        'severity': severity,
                                        'address': hex(start),
                                        'protection': protection,
                                        'technique': 'T1562 - Impair Defenses'
                                    })
                                    break
                            
                            # Check for known malware families
                            for family_name, (pattern, severity) in self.MALWARE_FAMILIES.items():
                                if re.search(pattern, data):
                                    detections.append({
                                        'type': 'Malware Family',
                                        'process': proc_name,
                                        'pid': proc_pid,
                                        'indicator': f'Possible {family_name.title()} infection',
                                        'severity': severity,
                                        'address': hex(start),
                                        'protection': protection,
                                        'technique': 'T1204 - User Execution'
                                    })
                                    break
                            
                            # Check for RAT signatures
                            for rat_name, (pattern, severity) in self.RAT_SIGNATURES.items():
                                if self._validate_detection(data, pattern, 8):
                                    detections.append({
                                        'type': 'Remote Access Trojan',
                                        'process': proc_name,
                                        'pid': proc_pid,
                                        'indicator': f'{rat_name.replace("_", " ").title()} detected',
                                        'severity': severity,
                                        'address': hex(start),
                                        'protection': protection,
                                        'technique': 'T1219 - Remote Access Software'
                                    })
                                    break
                            
                            # Check for cryptocurrency miner signatures
                            for miner_name, (pattern, severity) in self.CRYPTO_MINER_SIGNATURES.items():
                                if self._validate_detection(data, pattern, 8):
                                    detections.append({
                                        'type': 'Cryptocurrency Miner',
                                        'process': proc_name,
                                        'pid': proc_pid,
                                        'indicator': f'{miner_name.replace("_", " ").title()} detected',
                                        'severity': severity,
                                        'address': hex(start),
                                        'protection': protection,
                                        'technique': 'T1496 - Resource Hijacking'
                                    })
                                    break
                            
                            # Check for network indicators
                            for pattern_name, (pattern, severity) in self.NETWORK_PATTERNS.items():
                                if re.search(pattern, data):
                                    detections.append({
                                        'type': 'Network Activity',
                                        'process': proc_name,
                                        'pid': proc_pid,
                                        'indicator': pattern_name.replace('_', ' ').title(),
                                        'severity': severity,
                                        'address': hex(start),
                                        'protection': protection,
                                        'technique': 'T1071 - Application Layer Protocol'
                                    })
                                    break
                            
                            # Check for PE headers in non-mapped regions (Reflective DLL)
                            if data.startswith(b'MZ') and vad_file == "":
                                # Check for DOS stub and PE signature
                                if len(data) >= 0x40:
                                    pe_offset = struct.unpack('<I', data[0x3C:0x40])[0]
                                    if pe_offset < len(data) - 4:
                                        pe_sig = data[pe_offset:pe_offset+4]
                                        if pe_sig == b'PE\x00\x00':
                                            detections.append({
                                                'type': 'Reflective DLL Loading',
                                                'process': proc_name,
                                                'pid': proc_pid,
                                                'indicator': 'Valid PE in unmapped memory',
                                                'severity': 'Critical',
                                                'address': hex(start),
                                                'protection': protection,
                                                'technique': 'T1620 - Reflective Code Loading'
                                            })
                            
                            # Check for shellcode patterns
                            if re.search(rb'\x90{20,}', data):  # Long NOP sled
                                detections.append({
                                    'type': 'Shellcode Pattern',
                                    'process': proc_name,
                                    'pid': proc_pid,
                                    'indicator': 'Long NOP sled detected',
                                    'severity': 'High',
                                    'address': hex(start),
                                    'protection': protection,
                                    'technique': 'T1055 - Process Injection'
                                })
                            
                            # Check for common shellcode instructions
                            if re.search(rb'\x64\xa1\x30\x00\x00\x00', data):  # PEB access
                                detections.append({
                                    'type': 'Shellcode Pattern',
                                    'process': proc_name,
                                    'pid': proc_pid,
                                    'indicator': 'PEB access pattern (shellcode)',
                                    'severity': 'High',
                                    'address': hex(start),
                                    'protection': protection,
                                    'technique': 'T1055 - Process Injection'
                                })
                            
                        except exceptions.InvalidAddressException:
                            continue
                            
                except Exception as e:
                    vollog.debug(f"Error scanning VAD: {e}")
                    continue
                    
        except Exception as e:
            vollog.debug(f"Error scanning process memory: {e}")
        
        return detections
    
    def _check_process_hollowing(self, proc, proc_name: str, proc_pid: int) -> List[Dict]:
        """Detect process hollowing/doppelganging with enhanced checks."""
        detections = []
        
        try:
            peb = proc.get_peb()
            if not peb:
                return detections
            
            image_base = peb.ImageBaseAddress
            module_found = False
            expected_module_name = None
            
            for module in proc.load_order_modules():
                if module.DllBase == image_base:
                    module_found = True
                    try:
                        expected_module_name = module.BaseDllName.get_string()
                    except Exception:
                        pass
                    break
            
            if not module_found:
                detections.append({
                    'type': 'Process Hollowing',
                    'process': proc_name,
                    'pid': proc_pid,
                    'indicator': 'Mismatched image base address',
                    'severity': 'Critical',
                    'address': hex(image_base),
                    'protection': 'N/A',
                    'technique': 'T1055.012 - Process Hollowing'
                })
            elif expected_module_name and expected_module_name.lower() != proc_name:
                detections.append({
                    'type': 'Process Doppelgänging',
                    'process': proc_name,
                    'pid': proc_pid,
                    'indicator': f'Module mismatch: {expected_module_name}',
                    'severity': 'Critical',
                    'address': hex(image_base),
                    'protection': 'N/A',
                    'technique': 'T1055.013 - Process Doppelgänging'
                })
            
        except Exception as e:
            vollog.debug(f"Error checking process hollowing: {e}")
        
        return detections
    
    def _check_suspicious_parent_child(self, proc, proc_name: str, proc_pid: int, 
                                       kernel_module_name: str) -> List[Dict]:
        """Detect suspicious parent-child process relationships."""
        detections = []
        
        try:
            ppid = proc.InheritedFromUniqueProcessId
            
            parent_name = "Unknown"
            for parent_proc in pslist.PsList.list_processes(self.context, kernel_module_name):
                if parent_proc.UniqueProcessId == ppid:
                    parent_name = parent_proc.ImageFileName.cast(
                        "string",
                        max_length=parent_proc.ImageFileName.vol.count,
                        errors="replace"
                    ).lower()
                    break
            
            suspicious_relations = {
                'winword.exe': {
                    'children': ['powershell.exe', 'cmd.exe', 'wmic.exe', 'mshta.exe', 'certutil.exe', 'regsvr32.exe'],
                    'technique': 'T1566.001 - Spearphishing Attachment',
                    'severity': 'Critical'
                },
                'excel.exe': {
                    'children': ['powershell.exe', 'cmd.exe', 'wmic.exe', 'certutil.exe', 'regsvr32.exe'],
                    'technique': 'T1566.001 - Spearphishing Attachment',
                    'severity': 'Critical'
                },
                'outlook.exe': {
                    'children': ['powershell.exe', 'cmd.exe', 'wscript.exe', 'cscript.exe'],
                    'technique': 'T1566.002 - Spearphishing Link',
                    'severity': 'High'
                },
                'acrord32.exe': {
                    'children': ['powershell.exe', 'cmd.exe', 'wscript.exe'],
                    'technique': 'T1204.002 - Malicious File',
                    'severity': 'High'
                },
                'chrome.exe': {
                    'children': ['powershell.exe', 'cmd.exe', 'wscript.exe'],
                    'technique': 'T1566.002 - Spearphishing Link',
                    'severity': 'High'
                },
                'firefox.exe': {
                    'children': ['powershell.exe', 'cmd.exe', 'wscript.exe'],
                    'technique': 'T1566.002 - Spearphishing Link',
                    'severity': 'High'
                },
                'iexplore.exe': {
                    'children': ['powershell.exe', 'cmd.exe', 'wscript.exe'],
                    'technique': 'T1189 - Drive-by Compromise',
                    'severity': 'High'
                },
                'w3wp.exe': {
                    'children': ['powershell.exe', 'cmd.exe', 'net.exe'],
                    'technique': 'T1190 - Exploit Public-Facing Application',
                    'severity': 'Critical'
                },
                'sqlservr.exe': {
                    'children': ['powershell.exe', 'cmd.exe', 'xp_cmdshell'],
                    'technique': 'T1505.001 - SQL Stored Procedures',
                    'severity': 'Critical'
                },
            }
            
            for parent_pattern, config in suspicious_relations.items():
                if parent_pattern in parent_name and proc_name in config['children']:
                    detections.append({
                        'type': 'Suspicious Parent-Child',
                        'process': proc_name,
                        'pid': proc_pid,
                        'indicator': f'{parent_name} → {proc_name}',
                        'severity': config['severity'],
                        'address': f'PPID: {ppid}',
                        'protection': 'N/A',
                        'technique': config['technique']
                    })
            
        except Exception as e:
            vollog.debug(f"Error checking parent-child relationship: {e}")
        
        return detections
    
    def _check_lolbin_abuse(self, proc, proc_name: str, proc_pid: int) -> List[Dict]:
        """Detect Living off the Land binary abuse with enhanced command-line analysis."""
        detections = []
        
        if proc_name not in self.LOLBINS:
            return detections
        
        try:
            lolbin_info = self.LOLBINS[proc_name]
            lolbin_desc = lolbin_info[0]
            lolbin_technique = lolbin_info[1]
            
            peb = proc.get_peb()
            if peb:
                process_params = peb.ProcessParameters
                if process_params:
                    cmdline = process_params.CommandLine.get_string()
                    
                    suspicious_patterns = {
                        'http://': ('Remote HTTP Download', 'T1105 - Ingress Tool Transfer', 'Critical'),
                        'https://': ('Remote HTTPS Download', 'T1105 - Ingress Tool Transfer', 'High'),
                        'ftp://': ('FTP Transfer', 'T1105 - Ingress Tool Transfer', 'High'),
                        '-enc': ('Encoded Command', 'T1027 - Obfuscated Files', 'High'),
                        '-e ': ('Encoded Command', 'T1027 - Obfuscated Files', 'High'),
                        'frombase64': ('Base64 Decode', 'T1140 - Deobfuscate/Decode', 'High'),
                        'downloadstring': ('Web Download', 'T1105 - Ingress Tool Transfer', 'Critical'),
                        'downloadfile': ('File Download', 'T1105 - Ingress Tool Transfer', 'Critical'),
                        'invoke-expression': ('Dynamic Execution', 'T1059.001 - PowerShell', 'High'),
                        'iex': ('Dynamic Execution', 'T1059.001 - PowerShell', 'High'),
                        'bypass': ('Execution Policy Bypass', 'T1562.001 - Disable/Modify Tools', 'High'),
                        '-nop': ('No Profile', 'T1562.001 - Disable/Modify Tools', 'Medium'),
                        '-w hidden': ('Hidden Window', 'T1564.003 - Hidden Window', 'High'),
                        'windowstyle hidden': ('Hidden Window', 'T1564.003 - Hidden Window', 'High'),
                        'amsi': ('AMSI Bypass', 'T1562.001 - Disable/Modify Tools', 'Critical'),
                        '/delete': ('File Deletion', 'T1070.004 - File Deletion', 'Medium'),
                        '/create': ('Persistence Creation', 'T1053 - Scheduled Task', 'High'),
                        'vssadmin delete': ('Shadow Copy Deletion', 'T1490 - Inhibit System Recovery', 'Critical'),
                        'bcdedit': ('Boot Configuration', 'T1490 - Inhibit System Recovery', 'Critical'),
                        'wevtutil': ('Event Log Manipulation', 'T1070.001 - Clear Logs', 'Critical'),
                        '-urlcache': ('Download via certutil', 'T1105 - Ingress Tool Transfer', 'Critical'),
                        '-split': ('File splitting', 'T1140 - Deobfuscate/Decode', 'Medium'),
                        'invoke-mimikatz': ('Credential Dumping', 'T1003 - Credential Dumping', 'Critical'),
                        'invoke-webrequest': ('Web Request', 'T1105 - Ingress Tool Transfer', 'High'),
                        'start-bitstransfer': ('BITS Transfer', 'T1197 - BITS Jobs', 'High'),
                    }
                    
                    for pattern, (desc, technique, severity) in suspicious_patterns.items():
                        if pattern.lower() in cmdline.lower():
                            detections.append({
                                'type': 'LOLBin Abuse',
                                'process': proc_name,
                                'pid': proc_pid,
                                'indicator': f'{lolbin_desc}: {desc}',
                                'severity': severity,
                                'address': cmdline[:150] + '...' if len(cmdline) > 150 else cmdline,
                                'protection': 'N/A',
                                'technique': technique
                            })
                            break
                    
        except Exception as e:
            vollog.debug(f"Error checking LOLBin abuse: {e}")
        
        return detections
    
    def _check_dotnet_injection(self, proc, proc_name: str, proc_pid: int) -> List[Dict]:
        """Detect .NET assembly loading in suspicious processes."""
        detections = []
        
        try:
            clr_dlls = ['clr.dll', 'mscorlib.dll', 'mscoree.dll', 'clrjit.dll']
            loaded_clr = []
            
            for module in proc.load_order_modules():
                try:
                    dll_name = module.BaseDllName.get_string().lower()
                    if dll_name in clr_dlls:
                        loaded_clr.append(dll_name)
                except Exception:
                    continue
            
            expected_dotnet_procs = ['powershell.exe', 'pwsh.exe', 'msbuild.exe', 'csc.exe', 
                                    'vbc.exe', 'jsc.exe', 'regasm.exe', 'regsvcs.exe',
                                    'installutil.exe', 'devenv.exe', 'mscorsvw.exe',
                                    'explorer.exe', 'taskhost.exe', 'taskhostw.exe']  # Added legitimate processes
            
            if loaded_clr and proc_name not in expected_dotnet_procs:
                detection = {
                    'type': '.NET Injection',
                    'process': proc_name,
                    'pid': proc_pid,
                    'indicator': f'Unexpected CLR: {", ".join(loaded_clr)}',
                    'severity': 'High',
                    'address': 'N/A',
                    'protection': 'N/A',
                    'technique': 'T1055.001 - Dynamic-link Library Injection'
                }
                if not self._is_false_positive(proc_name, '.NET Injection', ''):
                    detections.append(detection)
                
        except Exception as e:
            vollog.debug(f"Error checking .NET injection: {e}")
        
        return detections
    
    def _check_suspicious_dlls(self, proc, proc_name: str, proc_pid: int) -> List[Dict]:
        """Check for suspicious or malicious DLLs loaded in process."""
        detections = []
        
        try:
            for module in proc.load_order_modules():
                try:
                    dll_name = module.BaseDllName.get_string().lower()
                    dll_path = module.FullDllName.get_string()
                    
                    # Check against known suspicious DLLs
                    if dll_name in self.SUSPICIOUS_DLLS:
                        detections.append({
                            'type': 'Suspicious DLL',
                            'process': proc_name,
                            'pid': proc_pid,
                            'indicator': f'Loaded: {dll_name}',
                            'severity': 'High',
                            'address': dll_path,
                            'protection': 'N/A',
                            'technique': 'T1055.001 - DLL Injection'
                        })
                    
                    # Check for DLLs loaded from suspicious paths
                    suspicious_paths = ['\\temp\\', '\\appdata\\local\\temp\\', '\\users\\public\\', '\\programdata\\']
                    for susp_path in suspicious_paths:
                        if susp_path in dll_path.lower():
                            detections.append({
                                'type': 'Suspicious DLL Path',
                                'process': proc_name,
                                'pid': proc_pid,
                                'indicator': f'{dll_name} from temp location',
                                'severity': 'Medium',
                                'address': dll_path,
                                'protection': 'N/A',
                                'technique': 'T1574.002 - DLL Side-Loading'
                            })
                            break
                    
                except Exception:
                    continue
                    
        except Exception as e:
            vollog.debug(f"Error checking suspicious DLLs: {e}")
        
        return detections
    
    def _check_thread_injection(self, proc, proc_name: str, proc_pid: int) -> List[Dict]:
        """Detect potential thread injection by checking for remote threads."""
        detections = []
        
        try:
            # Check for threads with different start addresses
            for thread in proc.ThreadListHead.list_of_type("_ETHREAD", "ThreadListEntry"):
                try:
                    start_addr = thread.Win32StartAddress
                    
                    # Check if start address is outside process modules
                    found_in_module = False
                    for module in proc.load_order_modules():
                        module_base = module.DllBase
                        module_size = module.SizeOfImage
                        if module_base <= start_addr < (module_base + module_size):
                            found_in_module = True
                            break
                    
                    if not found_in_module and start_addr != 0:
                        detections.append({
                            'type': 'Thread Injection',
                            'process': proc_name,
                            'pid': proc_pid,
                            'indicator': 'Thread with external start address',
                            'severity': 'High',
                            'address': hex(start_addr),
                            'protection': 'N/A',
                            'technique': 'T1055.003 - Thread Execution Hijacking'
                        })
                        break  # Only report once per process
                        
                except Exception:
                    continue
                    
        except Exception as e:
            vollog.debug(f"Error checking thread injection: {e}")
        
        return detections
    
    def _check_orphan_process(self, proc, proc_name: str, proc_pid: int, kernel_module_name: str) -> List[Dict]:
        """Detect orphan processes (parent no longer exists)."""
        detections = []
        
        try:
            ppid = proc.InheritedFromUniqueProcessId
            
            # System processes and init shouldn't be orphaned
            if proc_name in self.LEGITIMATE_PROCESSES:
                return detections
            
            # Check if parent exists
            parent_exists = False
            for parent_proc in pslist.PsList.list_processes(self.context, kernel_module_name):
                if parent_proc.UniqueProcessId == ppid:
                    parent_exists = True
                    break
            
            if not parent_exists and ppid not in [0, 4]:  # Exclude System PIDs
                detection = {
                    'type': 'Orphan Process',
                    'process': proc_name,
                    'pid': proc_pid,
                    'indicator': f'Parent PID {ppid} not found',
                    'severity': 'Medium',
                    'address': f'PPID: {ppid}',
                    'protection': 'N/A',
                    'technique': 'T1055 - Process Injection'
                }
                if not self._is_false_positive(proc_name, 'Orphan Process', ''):
                    detections.append(detection)
                
        except Exception as e:
            vollog.debug(f"Error checking orphan process: {e}")
        
        return detections
    
    def _check_code_integrity(self, proc, proc_name: str, proc_pid: int) -> List[Dict]:
        """Check for signs of code modification."""
        detections = []
        
        try:
            # Check for processes with modified executable sections
            for vad in proc.get_vad_root().traverse():
                try:
                    protection = vad.get_protection()
                    vad_file = vad.get_file_name()
                    
                    # Check for writable executable memory backed by a file
                    if 'EXECUTE' in protection and 'WRITE' in protection and vad_file != "":
                        detections.append({
                            'type': 'Code Modification',
                            'process': proc_name,
                            'pid': proc_pid,
                            'indicator': 'Writable executable section',
                            'severity': 'High',
                            'address': f'{vad_file}',
                            'protection': protection,
                            'technique': 'T1055.002 - Portable Executable Injection'
                        })
                        break
                        
                except Exception:
                    continue
                    
        except Exception as e:
            vollog.debug(f"Error checking code integrity: {e}")
        
        return detections
    
    def _generator(self):
        kernel_module_name = self.config["kernel"]
        target_pid = self.config.get("pid")
        verbose = self.config.get("verbose", False)
        min_severity = self.config.get("min-severity", 1)
        
        all_detections = []
        scanned_processes = 0
        
        for proc in pslist.PsList.list_processes(self.context, kernel_module_name):
            try:
                proc_name = proc.ImageFileName.cast(
                    "string",
                    max_length=proc.ImageFileName.vol.count,
                    errors="replace"
                ).lower()
                
                proc_pid = proc.UniqueProcessId
                
                if target_pid is not None and proc_pid != target_pid:
                    continue
                
                scanned_processes += 1
                if verbose:
                    vollog.info(f"Scanning process: {proc_name} (PID: {proc_pid})")
                
                detections = []
                
                # Run all detection methods
                detections.extend(self._check_suspicious_parent_child(proc, proc_name, proc_pid, kernel_module_name))
                detections.extend(self._check_lolbin_abuse(proc, proc_name, proc_pid))
                detections.extend(self._check_process_hollowing(proc, proc_name, proc_pid))
                detections.extend(self._check_dotnet_injection(proc, proc_name, proc_pid))
                detections.extend(self._check_suspicious_dlls(proc, proc_name, proc_pid))
                detections.extend(self._check_thread_injection(proc, proc_name, proc_pid))
                detections.extend(self._check_orphan_process(proc, proc_name, proc_pid, kernel_module_name))
                detections.extend(self._check_code_integrity(proc, proc_name, proc_pid))
                
                # Memory scanning (intensive - only for suspicious processes)
                if (proc_name in self.LOLBINS or 
                    'powershell' in proc_name or 
                    'cmd' in proc_name or
                    'wscript' in proc_name or
                    'cscript' in proc_name or
                    len(detections) > 0):  # Already suspicious
                    detections.extend(self._scan_process_memory(proc, proc_name, proc_pid))
                
                all_detections.extend(detections)
                
            except Exception as e:
                vollog.debug(f"Error processing process: {e}")
                continue
        
        # Filter by minimum severity
        severity_names = ['Low', 'Medium', 'High', 'Critical']
        if min_severity > 1:
            all_detections = [d for d in all_detections if self._get_severity_value(d['severity']) >= min_severity]
        
        # Calculate statistics
        critical_count = sum(1 for d in all_detections if d['severity'] == 'Critical')
        high_count = sum(1 for d in all_detections if d['severity'] == 'High')
        medium_count = sum(1 for d in all_detections if d['severity'] == 'Medium')
        low_count = sum(1 for d in all_detections if d['severity'] == 'Low')
        
        # Determine verdict
        verdict = "CLEAN"
        threat_level = "None"
        
        if critical_count >= 3:
            verdict = "CRITICAL INFECTION - IMMEDIATE ACTION REQUIRED"
            threat_level = "Extreme"
        elif critical_count > 0:
            verdict = "CRITICAL THREATS DETECTED"
            threat_level = "Critical"
        elif high_count >= 5:
            verdict = "SEVERE COMPROMISE - HIGH RISK"
            threat_level = "High"
        elif high_count > 2:
            verdict = "MULTIPLE THREATS DETECTED"
            threat_level = "High"
        elif high_count > 0:
            verdict = "THREATS DETECTED"
            threat_level = "Moderate"
        elif medium_count > 3:
            verdict = "SUSPICIOUS ACTIVITY"
            threat_level = "Low-Medium"
        elif medium_count > 0:
            verdict = "POTENTIAL THREATS"
            threat_level = "Low"
        
        # Header
        yield (0, (
            "==================================================",
            "FILELESS MALWARE HUNTER",
            "==================================================",
            "",
            "",
            "",
            ""
        ))
        
        yield (0, ("", "", "", "", "", "", ""))
        
        # Summary
        yield (0, (
            "VERDICT:",
            verdict,
            "",
            "",
            "",
            "",
            ""
        ))
        
        yield (0, (
            "THREAT LEVEL:",
            threat_level,
            "",
            "",
            "",
            "",
            ""
        ))
        
        yield (0, ("", "", "", "", "", "", ""))
        
        yield (0, (
            "SCAN STATISTICS:",
            f"Processes Scanned: {scanned_processes}",
            f"Total Detections: {len(all_detections)}",
            "",
            "",
            "",
            ""
        ))
        
        yield (0, (
            "SEVERITY BREAKDOWN:",
            f"Critical: {critical_count}",
            f"High: {high_count}",
            f"Medium: {medium_count}",
            f"Low: {low_count}",
            "",
            ""
        ))
        
        yield (0, ("", "", "", "", "", "", ""))
        yield (0, (
            "--------------------------------------------------",
            "DETAILED FINDINGS",
            "--------------------------------------------------",
            "",
            "",
            "",
            ""
        ))
        yield (0, ("", "", "", "", "", "", ""))
        
        # Group by severity
        critical_detections = [d for d in all_detections if d['severity'] == 'Critical']
        high_detections = [d for d in all_detections if d['severity'] == 'High']
        medium_detections = [d for d in all_detections if d['severity'] == 'Medium']
        low_detections = [d for d in all_detections if d['severity'] == 'Low']
        
        # Output Critical
        if critical_detections:
            yield (0, (
                "[CRITICAL SEVERITY]",
                "",
                "",
                "",
                "",
                "",
                ""
            ))
            
            for detection in critical_detections:
                yield (0, (
                    detection['type'],
                    detection['process'],
                    f"PID: {detection['pid']}",
                    detection['indicator'],
                    detection['severity'],
                    detection['address'][:80] if len(detection['address']) > 80 else detection['address'],
                    detection['technique']
                ))
            
            yield (0, ("", "", "", "", "", "", ""))
        
        # Output High
        if high_detections:
            yield (0, (
                "[HIGH SEVERITY]",
                "",
                "",
                "",
                "",
                "",
                ""
            ))
            
            for detection in high_detections:
                yield (0, (
                    detection['type'],
                    detection['process'],
                    f"PID: {detection['pid']}",
                    detection['indicator'],
                    detection['severity'],
                    detection['address'][:80] if len(detection['address']) > 80 else detection['address'],
                    detection['technique']
                ))
            
            yield (0, ("", "", "", "", "", "", ""))
        
        # Output Medium
        if medium_detections and min_severity <= 2:
            yield (0, (
                "[MEDIUM SEVERITY]",
                "",
                "",
                "",
                "",
                "",
                ""
            ))
            
            for detection in medium_detections:
                yield (0, (
                    detection['type'],
                    detection['process'],
                    f"PID: {detection['pid']}",
                    detection['indicator'],
                    detection['severity'],
                    detection['address'][:80] if len(detection['address']) > 80 else detection['address'],
                    detection['technique']
                ))
            
            yield (0, ("", "", "", "", "", "", ""))
        
        # Output Low (only if verbose)
        if low_detections and verbose and min_severity <= 1:
            yield (0, (
                "[LOW SEVERITY]",
                "",
                "",
                "",
                "",
                "",
                ""
            ))
            
            for detection in low_detections:
                yield (0, (
                    detection['type'],
                    detection['process'],
                    f"PID: {detection['pid']}",
                    detection['indicator'],
                    detection['severity'],
                    detection['address'][:80] if len(detection['address']) > 80 else detection['address'],
                    detection['technique']
                ))
            
            yield (0, ("", "", "", "", "", "", ""))
        
        # Footer
        if len(all_detections) == 0:
            yield (0, (
                "STATUS: NO THREATS DETECTED",
                "System appears clean based on fileless malware analysis.",
                "No suspicious memory artifacts found.",
                "",
                "",
                "",
                ""
            ))
        else:
            yield (0, (
                "==================================================",
                "END OF REPORT",
                "==================================================",
                "",
                "",
                "",
                ""
            ))
            
            if critical_count > 0 or high_count > 2:
                yield (0, (
                    "RECOMMENDATION:",
                    "Immediate incident response required.",
                    "Isolate system and conduct full forensic analysis.",
                    "",
                    "",
                    "",
                    ""
                ))
    
    def run(self):
        return renderers.TreeGrid(
            [
                ("Detection Type", str),
                ("Process", str),
                ("PID Info", str),
                ("Indicator", str),
                ("Severity", str),
                ("Address/Details", str),
                ("MITRE ATT&CK", str)
            ],
            self._generator(),
        )